package main

import (
	"net"
	"testing"
)

func TestIsHostAllowed_DotBoundary(t *testing.T) {
	p := NewPolicy([]string{"chatgpt.com", "*.openai.com"})

	allowed := []string{
		"chatgpt.com",
		"CHATGPT.COM",  // 大小写不敏感
		"chatgpt.com.", // FQDN 尾点
		"api.openai.com",
		"a.b.openai.com",
		"openai.com", // 裸域也放行
	}
	for _, h := range allowed {
		if !p.IsHostAllowed(h) {
			t.Errorf("应放行但被拒: %q", h)
		}
	}

	// 这一组是白名单实现最容易出错的地方：朴素的 HasSuffix("openai.com")
	// 会把前三个全部误放行。
	rejected := []string{
		"evilopenai.com",
		"notchatgpt.com",
		"openai.com.attacker.io",
		"chatgpt.com.evil.net",
		"example.com",
		"",
	}
	for _, h := range rejected {
		if p.IsHostAllowed(h) {
			t.Errorf("应拒绝但被放行: %q", h)
		}
	}
}

func TestIsHostAllowed_Wildcard(t *testing.T) {
	p := NewPolicy([]string{"*"})
	if !p.IsHostAllowed("anything.example.com") {
		t.Error("* 应放行任意域名")
	}
}

func TestIsBlockedIP(t *testing.T) {
	p := NewPolicy([]string{"*"})

	blocked := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254", // 云元数据端点
		"0.0.0.0",
		"100.64.0.1", // CGNAT
		"240.0.0.1",
		"255.255.255.255",
		"::1",
		"::",
		"fe80::1",
		"fc00::1",          // ULA
		"ff02::1",          // 组播
		"::ffff:127.0.0.1", // IPv4-mapped 回环——只按 v6 规则查会漏
		"::ffff:10.0.0.1",
		"::7f00:1",    // IPv4-compatible
		"2002::1",     // 6to4
		"2001:0:1::1", // Teredo
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("测试数据本身解析失败: %q", s)
		}
		if !p.IsBlockedIP(ip) {
			t.Errorf("应拦截但放行: %q", s)
		}
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "2604:2dc0:143:8200::1", "2606:4700::1111"}
	for _, s := range allowed {
		if p.IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("公网地址应放行但被拦: %q", s)
		}
	}

	if !p.IsBlockedIP(nil) {
		t.Error("nil 应当拦截")
	}
}

func TestCheckTarget_RejectsIPLiteralUnderAllowlist(t *testing.T) {
	p := NewPolicy([]string{"*.openai.com"})
	// 白名单是按域名写的，放行 IP 字面量等于给了绕过白名单的口子。
	if _, err := p.CheckTarget("1.1.1.1", 443); err == nil {
		t.Error("白名单模式下 IP 字面量应被拒绝")
	}
	if _, err := p.CheckTarget("evil.com", 443); err == nil {
		t.Error("白名单外域名应被拒绝")
	}
}

func TestCheckTarget_BadPort(t *testing.T) {
	p := NewPolicy([]string{"*"})
	for _, port := range []int{0, -1, 65536} {
		if _, err := p.CheckTarget("example.com", port); err == nil {
			t.Errorf("端口 %d 应被拒绝", port)
		}
	}
}
