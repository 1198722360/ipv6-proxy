package main

import (
	"fmt"
	"net"
	"strings"
)

// Policy 决定"允许连到哪里"。两道独立的闸：
//
//  1. 域名白名单——按名字过滤，在 DNS 解析之前。
//  2. 内网拦截——按解析出的 IP 过滤，在建立连接之前。
//
// 两道都要有。只有白名单挡不住 DNS 指向内网的域名；
// 只有内网拦截则任何公网目标都能借你的 IP 出去。
type Policy struct {
	allowAll bool
	exact    map[string]struct{}
	suffixes []string // "*.openai.com" 存成 ".openai.com"

	// lookup 可替换，只为让测试不依赖真实 DNS。生产恒为 net.LookupIP。
	lookup func(string) ([]net.IP, error)
}

func NewPolicy(patterns []string) *Policy {
	p := &Policy{exact: make(map[string]struct{}), lookup: net.LookupIP}
	for _, raw := range patterns {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern == "" {
			continue
		}
		if pattern == "*" {
			p.allowAll = true
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			p.suffixes = append(p.suffixes, pattern[1:]) // "*.a.com" -> ".a.com"
			continue
		}
		p.exact[pattern] = struct{}{}
	}
	return p
}

// IsHostAllowed 判断目标主机名是否在白名单内。
//
// 后缀匹配必须带上那个点。用 strings.HasSuffix(host, "openai.com") 的写法，
// "evilopenai.com" 会被判为放行——攻击者注册一个这样的域名就绕过了白名单。
// 存成 ".openai.com" 后缀就把边界钉在了标签分隔符上。
// 另外单独放行裸域本身（"openai.com" 匹配 "*.openai.com" 规则）。
func (p *Policy) IsHostAllowed(host string) bool {
	if p.allowAll {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".") // 去掉 FQDN 尾点，否则 "a.com." 匹配不上
	if h == "" {
		return false
	}
	if _, ok := p.exact[h]; ok {
		return true
	}
	for _, suffix := range p.suffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
		// ".openai.com" 也放行裸域 "openai.com"
		if h == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	return false
}

// IsBlockedIP 判断解析出的地址是不是不该碰的内网/特殊地址。
//
// 这是 SSRF 防线：没有它，代理就是一个"把内网暴露给外部调用方"的跳板，
// 云环境里 169.254.169.254 那个元数据端点尤其致命。
func (p *Policy) IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// ::ffff:127.0.0.1 这类 IPv4-mapped 地址无需手工还原：Go 的
	// IsLoopback/IsPrivate/IsLinkLocalUnicast 内部都会先调 To4()。
	// （Java 版必须自己处理这一层，那边漏了就等于放行整个内网。）
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsPrivate() {
		return true
	}

	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0: // 0.0.0.0/8
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // 100.64.0.0/10 CGNAT
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return true
		case v4[0] >= 240: // 240.0.0.0/4 保留 + 255.255.255.255
			return true
		}
		return false
	}

	// 以下按位判断假定 16 字节表示。长度异常的 net.IP 当作不可信直接拦，
	// 好过在索引处 panic 掉整个连接处理协程。
	if len(ip) != net.IPv6len {
		return true
	}

	// IPv6 专有的几段：::/128 与 ::1 上面已覆盖，这里补 IPv4-compatible
	// （::a.b.c.d，历史遗留，可被用来绕过朴素的 v6 检查）和 6to4/Teredo。
	if isIPv4Compatible(ip) {
		return true
	}
	if ip[0] == 0x20 && ip[1] == 0x02 { // 2002::/16 6to4
		return true
	}
	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 { // 2001::/32 Teredo
		return true
	}
	return false
}

// isIPv4Compatible 识别 ::a.b.c.d 形态（前 96 位为 0 且不是 :: 或 ::1）。
func isIPv4Compatible(ip net.IP) bool {
	if len(ip) != net.IPv6len {
		return false
	}
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	// 排除 :: 和 ::1
	return !(ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && (ip[15] == 0 || ip[15] == 1))
}

// CheckTarget 在拨号前做完整校验，返回可以安全连接的地址列表。
//
// 返回的是**已解析并逐个校验过的 IP**，调用方必须直接连这些 IP，
// 不能拿域名再解析一次。否则存在 DNS rebinding：第一次解析返回公网 IP
// 通过校验，第二次解析返回 127.0.0.1，实际连上的是内网。
func (p *Policy) CheckTarget(host string, port int) ([]net.IP, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("端口非法: %d", port)
	}
	if literal := net.ParseIP(host); literal != nil {
		// 目标直接给的是 IP 字面量。白名单是按域名写的，
		// 此时无法做名字匹配，只能靠内网拦截兜底；
		// 若白名单不是 "*"，则拒绝 IP 字面量——放行等于给了绕过白名单的口子。
		if !p.allowAll {
			return nil, fmt.Errorf("白名单模式下不允许直接以 IP 为目标: %s", host)
		}
		if p.IsBlockedIP(literal) {
			return nil, fmt.Errorf("目标地址属于内网/保留网段: %s", host)
		}
		return []net.IP{literal}, nil
	}

	if !p.IsHostAllowed(host) {
		return nil, fmt.Errorf("目标不在白名单内: %s", host)
	}

	ips, err := p.lookup(host)
	if err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", host, err)
	}
	var safe []net.IP
	for _, ip := range ips {
		if p.IsBlockedIP(ip) {
			// 一个被解析到内网的域名，整体拒绝而不是跳过这一条。
			// 跳过意味着"DNS 里混一条内网记录"这种攻击只会被静默忽略。
			return nil, fmt.Errorf("%s 解析到内网地址 %s，已拒绝", host, ip)
		}
		safe = append(safe, ip)
	}
	if len(safe) == 0 {
		return nil, fmt.Errorf("%s 没有可用地址", host)
	}
	return safe, nil
}
