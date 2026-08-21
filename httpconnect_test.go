package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestParseProxyAuth_Rejects(t *testing.T) {
	cases := []string{
		"",
		"Bearer abc",
		"Basic !!!not-base64!!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")),
	}
	for _, h := range cases {
		if _, _, ok := parseProxyAuth(h); ok {
			t.Errorf("应拒绝: %q", h)
		}
	}
}

func TestParseProxyAuth_CaseInsensitiveScheme(t *testing.T) {
	h := "basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	if _, _, ok := parseProxyAuth(h); !ok {
		t.Error("scheme 应大小写不敏感")
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"chatgpt.com:443", "chatgpt.com", 443},
		{"chatgpt.com", "chatgpt.com", 443},
		{"example.com:8443", "example.com", 8443},
		{"[2606:4700::1]:443", "2606:4700::1", 443},
	}
	for _, c := range cases {
		host, port, err := splitHostPortDefault(c.in, 443)
		if err != nil {
			t.Errorf("%q 报错: %v", c.in, err)
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("%q: 期望 %s:%d, 得到 %s:%d", c.in, c.wantHost, c.wantPort, host, port)
		}
	}

	for _, bad := range []string{"", "host:0", "host:99999", "host:abc"} {
		if _, _, err := splitHostPortDefault(bad, 443); err == nil {
			t.Errorf("应拒绝 %q", bad)
		}
	}
}

func TestParseProxyAuth_DashUsername(t *testing.T) {
	// 用户名是破折号形态，不含冒号，按 RFC 7617 首冒号拆分即可。
	user := "2604-2dc0-143-8200--1"
	pass := "s3cret"
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	gotUser, gotPass, ok := parseProxyAuth(header)
	if !ok {
		t.Fatal("解析失败")
	}
	if gotUser != user {
		t.Errorf("用户名: 期望 %q, 得到 %q", user, gotUser)
	}
	if gotPass != pass {
		t.Errorf("口令: 期望 %q, 得到 %q", pass, gotPass)
	}
}

func TestParseProxyAuth_PasswordMayContainColon(t *testing.T) {
	// RFC 7617：口令可以含冒号，只有用户名不能。
	user := "2604-2dc0-143-8200--1"
	pass := "pa:ss:word"
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	gotUser, gotPass, ok := parseProxyAuth(header)
	if !ok {
		t.Fatal("解析失败")
	}
	if gotUser != user || gotPass != pass {
		t.Errorf("期望 %q/%q, 得到 %q/%q", user, pass, gotUser, gotPass)
	}
}

// 错误响应必须带上可读的 body。曾经这里是 `_ = msg`——信息被构造出来又丢掉，
// 客户端只看到一个空的 405，而用代理的人通常看不到服务端日志。
func TestWriteHTTPError_IncludesBody(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		writeHTTPError(server, http.StatusMethodNotAllowed, "只支持 CONNECT")
		_ = server.Close()
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("读响应失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("状态码 = %d, 期望 405", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读 body 失败: %v", err)
	}
	if !strings.Contains(string(body), "只支持 CONNECT") {
		t.Errorf("body 里没有错误信息，得到 %q", body)
	}
}
