package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeDialer 绕开真实的源地址绑定：单测机器上不会有可用的 IPv6 前缀，
// 但握手、认证、策略这些逻辑与拨号无关，值得单独覆盖。
type fakeDialer struct {
	target     string // 真实回环 echo 服务的地址
	lastSource net.IP
	fail       bool
}

func (f *fakeDialer) DialFirst(ctx context.Context, source net.IP, targets []net.IP, port int) (net.Conn, error) {
	f.lastSource = source
	if f.fail {
		return nil, fmt.Errorf("模拟拨号失败")
	}
	return net.Dial("tcp", f.target)
}

// startEcho 起一个把收到的内容原样回写的 TCP 服务，充当"上游"。
func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 echo 失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func startTestServer(t *testing.T, allowed []string) (*Server, *fakeDialer) {
	t.Helper()
	echo := startEcho(t)

	cfg := &Config{
		Listen:       "127.0.0.1:0",
		Password:     "testpass",
		AllowedHosts: allowed,
		DialTimeout:  3 * time.Second,
		IdleTimeout:  5 * time.Second,
		MaxConns:     16,
	}
	resolver, err := NewPrefixResolver("2604:2dc0:143:8200::/56")
	if err != nil {
		t.Fatalf("前缀构造失败: %v", err)
	}
	fd := &fakeDialer{target: echo.Addr().String()}
	policy := NewPolicy(cfg.AllowedHosts)
	// 固定 DNS 结果，测试不该依赖外网可达性或真实解析结果。
	policy.lookup = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2606:4700::1111")}, nil
	}
	srv := NewServer(cfg, policy, resolver)
	srv.dialer = fd

	ready := make(chan struct{})
	go func() {
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			panic(err)
		}
		srv.listener = ln
		close(ready)
		srv.serveLoop(ln)
	}()
	<-ready
	t.Cleanup(func() { _ = srv.Close() })
	return srv, fd
}

// dialProxy 连到被测服务，并设置读超时——握手一旦卡住，
// 测试应该在几秒内失败，而不是拖到整个测试套件超时。
func dialProxy(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", srv.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// socks5Handshake 走完方法协商 + 认证 + CONNECT，返回最终应答码。
func socks5Handshake(t *testing.T, c net.Conn, user, pass, host string, port int) byte {
	t.Helper()
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("写方法协商失败: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("读方法应答失败: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("方法应答异常: %v", resp)
	}

	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := c.Write(auth); err != nil {
		t.Fatalf("写认证失败: %v", err)
	}
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("读认证应答失败: %v", err)
	}
	if resp[1] != 0x00 {
		return 0xFE // 认证被拒的哨兵值
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("写 CONNECT 失败: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("读 CONNECT 应答失败: %v", err)
	}
	return reply[1]
}

func TestSocks5_EndToEnd(t *testing.T) {
	srv, fd := startTestServer(t, []string{"chatgpt.com", "*.openai.com"})
	c := dialProxy(t, srv)

	source := "2604-2dc0-143-8200--7"
	if rep := socks5Handshake(t, c, source, "testpass", "chatgpt.com", 443); rep != 0x00 {
		t.Fatalf("期望成功，得到应答码 0x%02x", rep)
	}

	// 用户名确实被当成出口地址传给了拨号器
	// 破折号形态被正确翻译成冒号形态传给了拨号器
	if fd.lastSource == nil || fd.lastSource.String() != "2604:2dc0:143:8200::7" {
		t.Errorf("出口地址: 期望 2604:2dc0:143:8200::7, 得到 %v", fd.lastSource)
	}

	// 隧道真的通了
	payload := []byte("hello through the tunnel")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("写隧道失败: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("读隧道失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("回显不符: %q", got)
	}
}

func TestSocks5_WrongPassword(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)
	if rep := socks5Handshake(t, c, "2604-2dc0-143-8200--1", "wrong", "chatgpt.com", 443); rep != 0xFE {
		t.Errorf("错误口令应在认证阶段被拒，得到 0x%02x", rep)
	}
}

func TestSocks5_UsernameOutsidePrefix(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)
	// 口令对，但出口地址不在允许的前缀内——这是防"绑任意源地址"的那道闸。
	if rep := socks5Handshake(t, c, "2001-db8--1", "testpass", "chatgpt.com", 443); rep != 0xFE {
		t.Errorf("越界出口地址应被拒，得到 0x%02x", rep)
	}
}

func TestSocks5_TargetNotAllowed(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*.openai.com"})
	c := dialProxy(t, srv)
	rep := socks5Handshake(t, c, "2604-2dc0-143-8200--1", "testpass", "evilopenai.com", 443)
	if rep != repNotAllowed {
		t.Errorf("白名单外目标应回 0x02，得到 0x%02x", rep)
	}
}

func TestHTTPConnect_EndToEnd(t *testing.T) {
	srv, fd := startTestServer(t, []string{"chatgpt.com"})
	c := dialProxy(t, srv)

	source := "2604-2dc0-143-8299--abcd"
	cred := base64.StdEncoding.EncodeToString([]byte(source + ":testpass"))
	req := "CONNECT chatgpt.com:443 HTTP/1.1\r\n" +
		"Host: chatgpt.com:443\r\n" +
		"Proxy-Authorization: Basic " + cred + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("写 CONNECT 失败: %v", err)
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读应答失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，得到 %d", resp.StatusCode)
	}
	if fd.lastSource == nil || fd.lastSource.String() != "2604:2dc0:143:8299::abcd" {
		t.Errorf("出口地址: 期望 2604:2dc0:143:8299::abcd, 得到 %v", fd.lastSource)
	}

	payload := []byte("tunnel payload")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("写隧道失败: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("读隧道失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("回显不符: %q", got)
	}
}

func TestHTTPConnect_MissingAuth(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)
	if _, err := c.Write([]byte("CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("读应答失败: %v", err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("期望 407，得到 %d", resp.StatusCode)
	}
	// 没有这个头，curl 之类的客户端不会带凭据重试。
	if !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic") {
		t.Errorf("407 必须带 Proxy-Authenticate，得到 %q", resp.Header.Get("Proxy-Authenticate"))
	}
}

func TestHTTPConnect_TargetNotAllowed(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*.openai.com"})
	c := dialProxy(t, srv)
	cred := base64.StdEncoding.EncodeToString([]byte("2604-2dc0-143-8200--1:testpass"))
	req := "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n" +
		"Proxy-Authorization: Basic " + cred + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("读应答失败: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("期望 403，得到 %d", resp.StatusCode)
	}
}

func TestHTTPConnect_NonConnectRejected(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)
	if _, err := c.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("读应答失败: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("期望 405，得到 %d", resp.StatusCode)
	}
}

// 协议嗅探的核心风险：SOCKS5 客户端通常把 "05 01 02" 三个字节一起发出，
// Peek(1) 会把三个字节全读进缓冲区。如果后续逻辑绕过缓冲区直接读 socket，
// 握手会永久挂起。这个用例专门钉住它。
func TestProtocolSniffing_SinglePacketHandshake(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)

	full := []byte{0x05, 0x01, 0x02}
	user := "2604-2dc0-143-8200--1"
	full = append(full, 0x01, byte(len(user)))
	full = append(full, user...)
	full = append(full, byte(len("testpass")))
	full = append(full, "testpass"...)
	// 方法协商 + 认证一次性发出
	if _, err := c.Write(full); err != nil {
		t.Fatalf("写失败: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("读方法应答失败（很可能是缓冲区字节被丢弃）: %v", err)
	}
	if resp[1] != 0x02 {
		t.Fatalf("方法应答异常: %v", resp)
	}
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("读认证应答失败: %v", err)
	}
	if resp[1] != 0x00 {
		t.Errorf("认证应成功，得到 0x%02x", resp[1])
	}
}

func TestSocks5_NoAuthMethodRejected(t *testing.T) {
	srv, _ := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)
	// 客户端只提供 NO_AUTH。开放代理绝不能接受它。
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("读失败: %v", err)
	}
	if resp[1] != methodNoneAccept {
		t.Errorf("应回 0xFF 拒绝，得到 0x%02x", resp[1])
	}
}

// 冒号形态的用户名会被 curl 之流在发出前切碎，服务端拿到的是碎片。
// 这个用例钉住：这种情况必须被拒绝，且不会因为拼接猜测而意外放行。
func TestSocks5_ColonUsernameRejected(t *testing.T) {
	srv, fd := startTestServer(t, []string{"*"})
	c := dialProxy(t, srv)

	// 模拟 curl 的行为：按第一个冒号拆 "2604:2dc0:143:8200::1:testpass"
	rep := socks5Handshake(t, c, "2604", "2dc0:143:8200::1:testpass", "chatgpt.com", 443)
	if rep != 0xFE {
		t.Errorf("被切碎的凭据应在认证阶段被拒，得到 0x%02x", rep)
	}
	if fd.lastSource != nil {
		t.Error("认证失败时不应发生拨号")
	}
}
