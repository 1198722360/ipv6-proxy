package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Dialer 只暴露服务真正用到的那一个方法，让测试能注入一个不需要
// 真实 IPv6 前缀的假拨号器——否则端到端测试必须依赖机器的网络配置。
type Dialer interface {
	DialFirst(ctx context.Context, source net.IP, targets []net.IP, port int) (net.Conn, error)
}

// BoundDialer 用指定的本地 IPv6 作为源地址向外拨号。
//
// 整个服务的存在意义就在这个结构体上：出口 IP 由调用方按连接指定，
// 而不是由系统路由决定。
type BoundDialer struct {
	Timeout time.Duration
}

// DialFrom 从 source 出发连到 target。
//
// 绑定源地址要求内核允许绑定一个本机没有实际配置的地址
// （net.ipv6.ip_nonlocal_bind=1 + 一条指向 lo 的 local 路由）。
// 没配置的话这里会直接报 "cannot assign requested address"——
// 这个错误要原样透给调用方，它比任何包装过的信息都更好排查。
func (d *BoundDialer) DialFrom(ctx context.Context, source net.IP, target net.IP, port int) (net.Conn, error) {
	local := &net.TCPAddr{IP: source}

	dialer := &net.Dialer{
		LocalAddr: local,
		Timeout:   d.Timeout,
		// 显式关掉 Happy Eyeballs 的双栈回退：源地址已经钉死是 v6，
		// 回落到 v4 会绑定失败，不如直接失败得干脆。
		FallbackDelay: -1,
		// 在 bind() 之前打开 FREEBIND，否则绑一个本机没配置的地址
		// 会直接 EADDRNOTAVAIL。/56 里有 7.2e16 个地址，不可能预先配上去。
		Control: setFreebind,
	}

	network := "tcp6"
	if target.To4() != nil {
		// 目标是 v4 时源地址绑不上去，这种组合本身就是配置错误。
		return nil, fmt.Errorf("出口为 IPv6 但目标 %s 是 IPv4，无法绑定", target)
	}

	addr := net.JoinHostPort(target.String(), fmt.Sprint(port))
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("从 %s 连接 %s 失败: %w", source, addr, err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		// KeepAlive 让半死连接最终被回收；rt 刷新是短交互，
		// 但 CONNECT 隧道可能长时间静默。
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(60 * time.Second)
	}
	return conn, nil
}

// DialFirst 依次尝试候选地址，返回第一个连成功的。
//
// 一个域名可能解析出多个 AAAA，只试第一个会在那台机器故障时整体失败。
func (d *BoundDialer) DialFirst(ctx context.Context, source net.IP, targets []net.IP, port int) (net.Conn, error) {
	var lastErr error
	for _, target := range targets {
		if target.To4() != nil {
			continue // v6 出口连不了 v4 目标，跳过而不是报错——可能还有 AAAA 在后面
		}
		conn, err := d.DialFrom(ctx, source, target, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("目标没有可用的 IPv6 地址")
	}
	return nil, lastErr
}

// relay 双向转发，任一方向结束就关掉两端。
//
// 用 CloseWrite 传递半关闭：直接 Close 会让对端把"上传完成"误判成"连接异常"，
// 某些上游会因此丢掉还没发完的响应体。
func relay(a, b net.Conn, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			if idle > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idle))
			}
			n, err := src.Read(buf)
			if n > 0 {
				if idle > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idle))
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// bindOnly 只做绑定、不发起连接，用于启动自检和测试。
// 返回 nil 表示这个源地址可以绑定。
func bindOnly(source net.IP) error {
	lc := net.ListenConfig{Control: setFreebind}
	conn, err := lc.Listen(context.Background(), "tcp6", net.JoinHostPort(source.String(), "0"))
	if err != nil {
		return err
	}
	return conn.Close()
}
