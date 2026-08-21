package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleHTTP 处理 HTTP 代理连接。只支持 CONNECT。
//
// 不支持明文 HTTP 代理（GET http://... 那种形态）是有意的：
// 目标全是 HTTPS，实现明文转发只会多一条需要同样做策略校验的代码路径。
func (s *Server) handleHTTP(conn net.Conn, buffered *bufio.Reader) error {
	// 同 handleSocks5：整条链路只取一次快照。
	cfg := s.cfg.Load()
	policy := s.policy.Load()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	req, err := http.ReadRequest(buffered)
	if err != nil {
		return fmt.Errorf("解析 HTTP 请求失败: %w", err)
	}

	if req.Method != http.MethodConnect {
		writeHTTPError(conn, http.StatusMethodNotAllowed, "只支持 CONNECT")
		return fmt.Errorf("不支持的方法 %s", req.Method)
	}

	username, password, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		// 407 必须带 Proxy-Authenticate，否则 curl 之类的客户端不会重试带凭据。
		resp := &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{
				"Proxy-Authenticate": []string{`Basic realm="ipv6-proxy"`},
				"Connection":         []string{"close"},
			},
		}
		_ = resp.Write(conn)
		return fmt.Errorf("缺少 Proxy-Authorization")
	}

	source, authErr := s.authenticate(cfg, username, password)
	if authErr != nil {
		writeHTTPError(conn, http.StatusProxyAuthRequired, "认证失败")
		return authErr
	}

	host, port, err := splitHostPortDefault(req.Host, 443)
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "目标地址非法")
		return err
	}

	targets, err := policy.CheckTarget(host, port)
	if err != nil {
		writeHTTPError(conn, http.StatusForbidden, "目标被策略拒绝")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()
	upstream, err := s.dialer.DialFirst(ctx, source, targets, port)
	if err != nil {
		writeHTTPError(conn, http.StatusBadGateway, "连接上游失败")
		return err
	}

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = upstream.Close()
		return err
	}

	_ = conn.SetDeadline(time.Time{})
	s.stats.RecordConnection("http", conn.RemoteAddr(), host, port, source)
	s.logf("http %s -> %s:%d (出口 %s)", conn.RemoteAddr(), host, port, source)

	// 客户端可能在 CONNECT 之后立刻就把 TLS ClientHello 粘在同一个包里发来，
	// 这部分已经躺在 bufio 的缓冲区里。不先把它冲给上游，握手就会永远卡住。
	if n := buffered.Buffered(); n > 0 {
		pending, _ := buffered.Peek(n)
		if _, err := upstream.Write(pending); err != nil {
			_ = upstream.Close()
			return err
		}
		_, _ = buffered.Discard(n)
	}

	relay(conn, upstream, cfg.IdleTimeout)
	return nil
}

// parseProxyAuth 解析 Basic 凭据。
func parseProxyAuth(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	raw := string(decoded)
	// 按**第一个**冒号拆，即 RFC 7617 的规定：用户名不含冒号，口令可以含。
	// 用户名是破折号形态的 IPv6，本来就没有冒号，所以这里不再有歧义。
	idx := strings.Index(raw, ":")
	if idx < 0 {
		return "", "", false
	}
	return raw[:idx], raw[idx+1:], true
}

// splitHostPortDefault 拆 "host:port"，没端口时用默认值。
func splitHostPortDefault(hostport string, defaultPort int) (string, int, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0, fmt.Errorf("目标为空")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// 没端口。注意裸 IPv6 字面量（不带方括号）在这里也会走进来，
		// 但 CONNECT 的目标按规范必须带端口，所以当作无端口域名处理即可。
		return strings.Trim(hostport, "[]"), defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("端口非法: %q", portStr)
	}
	return host, port, nil
}

func writeHTTPError(conn net.Conn, code int, msg string) {
	// msg 必须真的写进 body。此前这里是 `_ = msg`——错误信息被构造出来又丢掉，
	// 客户端只收到一个空的 405，看不出到底哪里不对。
	// 服务端日志里有原因，但用代理的人通常看不到服务端日志。
	body := msg + "\n"
	resp := &http.Response{
		StatusCode: code,
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{
			"Connection":   []string{"close"},
			"Content-Type": []string{"text/plain; charset=utf-8"},
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	_ = resp.Write(conn)
}
