package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server 在**一个端口**上同时提供 SOCKS5 和 HTTP CONNECT。
//
// 单端口是刻意的：两个端口意味着两份防火墙规则、两个要记住的数字。
// 靠第一个字节就能无歧义区分——SOCKS5 一定以 0x05 开头，
// 而 HTTP 方法名全是 ASCII 字母，不可能是 0x05。
type Server struct {
	// cfg 与 policy 用原子指针而非裸指针，因为管理面能在运行期替换它们。
	//
	// 必须是**整体替换**，不能原地改字段：
	//   - Config.Password 是 string（两字长），撕裂读会读到长度和数据不匹配的值；
	//   - Policy.exact 是 map，并发读写会直接 fatal error 打死整个进程，
	//     那是 runtime 主动崩溃，recover 接不住。
	// 换成写时复制之后，每个连接开头取一次快照，整条链路用同一份，
	// 既没有竞态，也不会出现"同一个请求前半段用旧白名单、后半段用新的"。
	cfg      atomic.Pointer[Config]
	policy   atomic.Pointer[Policy]
	resolver *PrefixResolver // 出口前缀不在可改范围内，保持裸指针
	dialer   Dialer

	stats    *Stats
	listener net.Listener
	wg       sync.WaitGroup
	closing  atomic.Bool
	active   atomic.Int64
}

func NewServer(cfg *Config, policy *Policy, resolver *PrefixResolver) *Server {
	s := &Server{
		resolver: resolver,
		// 注意：BoundDialer.Timeout 是 cfg.DialTimeout 在此刻的**快照**。
		// 超时项不在可改范围内，所以这份副本不会过期。将来若要让超时可改，
		// 记得连这里一起换掉——只改 Config 是不够的。
		dialer: &BoundDialer{Timeout: cfg.DialTimeout},
		stats:  NewStats(),
	}
	s.cfg.Store(cfg)
	s.policy.Store(policy)
	return s
}

// Config 返回当前配置快照。调用方拿到后应一直用这一份。
func (s *Server) Config() *Config { return s.cfg.Load() }

// Policy 返回当前策略快照。
func (s *Server) Policy() *Policy { return s.policy.Load() }

func (s *Server) ListenAndServe() error {
	listen := s.cfg.Load().Listen
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", listen, err)
	}
	s.listener = ln
	log.Printf("监听 %s（SOCKS5 + HTTP CONNECT 同端口）", ln.Addr())
	return s.serveLoop(ln)
}

// serveLoop 与 ListenAndServe 分开，是为了让测试可以先拿到已绑定的
// listener（端口 0 需要绑定后才知道实际端口），再启动接受循环。
func (s *Server) serveLoop(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closing.Load() {
				break
			}
			// 临时性错误（fd 耗尽等）不该让整个服务退出。
			var ne net.Error
			if ok := asNetError(err, &ne); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("accept 失败: %w", err)
		}

		if maxConns := s.cfg.Load().MaxConns; int(s.active.Add(1)) > maxConns {
			s.active.Add(-1)
			_ = conn.Close()
			s.stats.RecordRejected(conn.RemoteAddr(), fmt.Sprintf("连接数超过上限 %d", maxConns))
			log.Printf("连接数超过上限 %d，拒绝 %s", maxConns, conn.RemoteAddr())
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.active.Add(-1)
			defer conn.Close()
			if err := s.handle(conn); err != nil {
				s.stats.RecordFailed(conn.RemoteAddr(), err)
				log.Printf("连接 %s 结束: %v", conn.RemoteAddr(), err)
			}
		}()
	}
	s.wg.Wait()
	return nil
}

// handle 嗅探首字节决定走哪个协议。
func (s *Server) handle(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReaderSize(conn, 8*1024)
	first, err := reader.Peek(1)
	if err != nil {
		// 连上就断、一个字节都没发的连接（端口扫描、TCP 健康检查、
		// 负载均衡探活）不记进状态页。这类连接每天可能有成千上万条，
		// 记下来会把 200 条的环形缓冲冲干净，真正需要排查的记录反而看不到了。
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("读取首字节失败: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	if first[0] == socks5Version {
		_, _ = reader.Discard(1)
		// 必须继续从 reader 读，不能退回裸 conn：Peek(1) 触发的是一次完整的
		// socket 读，客户端的 "05 01 02" 通常一个包就到齐了，后两个字节
		// 此刻躺在 bufio 缓冲区里。绕过 reader 直接读 conn 会永远等不到它们。
		return s.handleSocks5(&prefixConn{Conn: conn, reader: reader}, socks5Version)
	}
	return s.handleHTTP(conn, reader)
}

func (s *Server) Close() error {
	s.closing.Store(true)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) logf(format string, args ...any) {
	log.Printf(format, args...)
}

// prefixConn 让 Conn 的读路径走已经缓冲了数据的 bufio.Reader，
// 写路径和 deadline 仍然直达底层 Conn。
type prefixConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func asNetError(err error, target *net.Error) bool {
	if ne, ok := err.(net.Error); ok {
		*target = ne
		return true
	}
	return false
}
