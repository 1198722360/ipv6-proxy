package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// PrefixResolver 持有"出口地址必须落在哪个前缀内"这条规则。
//
// 这是整个服务最重要的安全边界。出口地址由客户端通过用户名传入，
// 如果不校验，这个代理就变成了"绑任意源地址发包"的工具：
// 别人可以让你的机器用不属于它的源 IP 发送流量。
// 校验之后，最坏情况也只是在你自己的地址块里换个地址。
type PrefixResolver struct {
	prefix *net.IPNet
	source string // "config" 或 "auto:<网卡名>"，只用于启动日志
}

// NewPrefixResolver 解析前缀。raw 为空或 "auto" 时从网卡探测。
//
// 探测失败直接返回错误而不是放行——没有前缀就没有边界，
// 静默降级成"接受任意地址"是最糟糕的失败方式。
func NewPrefixResolver(raw string) (*PrefixResolver, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") {
		prefix, ifaceName, err := detectPrefix()
		if err != nil {
			return nil, err
		}
		return &PrefixResolver{prefix: prefix, source: "auto:" + ifaceName}, nil
	}

	// ParseCIDR 的第二个返回值已经把主机位清零了。
	// （Java 版这里踩过坑：手写的位清除写成了自我拷贝的空操作，
	//   探测出的前缀里残留主机位，导致包含性判断整体失真。Go 这里由标准库保证。）
	ip, network, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, fmt.Errorf("PROXY_IPV6_PREFIX 不是合法 CIDR: %q: %w", raw, err)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("PROXY_IPV6_PREFIX 必须是 IPv6 前缀，收到 %q", raw)
	}
	ones, _ := network.Mask.Size()
	if ones < 16 || ones > 128 {
		return nil, fmt.Errorf("前缀长度 /%d 不合理，应在 /16 ~ /128 之间", ones)
	}
	return &PrefixResolver{prefix: network, source: "config"}, nil
}

func (p *PrefixResolver) String() string {
	return fmt.Sprintf("%s (%s)", p.prefix.String(), p.source)
}

// Resolve 把用户名（破折号形态的 IPv6）转成可用于绑定的源地址。
//
// 拒绝的五类：含冒号、解析失败、不是 IPv6、不在前缀内、以及特殊用途地址
// （回环 / 链路本地 / 组播 / 未指定）。最后一类即使碰巧落在前缀内
// 也不该作为出口——它们出不了本机。
func (p *PrefixResolver) Resolve(raw string) (net.IP, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("出口地址为空")
	}
	// 用户名一律用破折号形态：2604-2dc0-143-8200--1 表示 2604:2dc0:143:8200::1。
	//
	// 冒号形态明确拒绝，不做兼容。原因是凭据里的冒号是分隔符：
	// curl 的 --proxy-user 和 RFC 7617 的 Basic 都规定用户名不含冒号、
	// 按第一个冒号拆分。含冒号的用户名会被客户端在发出前就切碎，
	// 服务端再怎么兜底都只是在猜哪一段是地址、哪一段是口令。
	// 从格式上排除冒号，这类歧义就不存在了。
	if strings.ContainsAny(raw, ":[]") {
		return nil, fmt.Errorf("出口地址不能含冒号，请用破折号形态（如 2604-2dc0-143-8200--1）: %q", raw)
	}
	// 也容忍 %eth0 这种 zone 后缀，绑定时用不上。
	if idx := strings.IndexByte(raw, '%'); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.ReplaceAll(raw, "-", ":")

	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("出口地址不是合法 IP: %q", raw)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("出口地址必须是 IPv6: %q", raw)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return nil, fmt.Errorf("出口地址是特殊用途地址，不能作为出口: %q", raw)
	}
	if !p.prefix.Contains(ip) {
		return nil, fmt.Errorf("出口地址 %q 不在允许的前缀 %s 内", raw, p.prefix)
	}
	return ip, nil
}

// detectPrefix 从网卡上找一个全球单播 IPv6 地址，用它的掩码算出前缀。
//
// 注意：探测得到的是**网卡上宣告的**前缀，通常是 /64。
// 如果你的服务商路由给你的是更大的块（比如 /56），探测结果只覆盖其中
// 一个 /64，那些落在其他 /64 的地址会被拒。这种情况必须显式配置
// PROXY_IPV6_PREFIX，探测帮不了你。
func detectPrefix() (*net.IPNet, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", fmt.Errorf("枚举网卡失败: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() != nil {
				continue
			}
			ip := ipnet.IP
			if !ip.IsGlobalUnicast() || ip.IsPrivate() {
				// IsPrivate 对 v6 覆盖 fc00::/7（ULA）。ULA 出不了公网，
				// 拿它当出口前缀等于让所有请求失败。
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 128 || ones == 0 || ones == 128 {
				// /128 说明网卡只有单地址、没有可用块，探测不出有意义的前缀。
				continue
			}
			network := &net.IPNet{
				IP:   ip.Mask(ipnet.Mask),
				Mask: ipnet.Mask,
			}
			return network, iface.Name, nil
		}
	}
	return nil, "", fmt.Errorf("未探测到可用的全球单播 IPv6 前缀；请显式设置 PROXY_IPV6_PREFIX")
}

// ProbeAddress 在前缀内挑一个确定的地址，供部署脚本做端到端自检。
//
// 单独做成一个函数（而不是让部署脚本拼字符串）是因为窄前缀会出错：
// 脚本里 "${PREFIX%::*}::7ea3:1" 这种写法对 /56 恰好正确，但对 /120
// 算出来的地址落在前缀之外，服务端会以"不在允许的前缀内"拒绝——
// 于是自检失败，而实际配置一切正常。用同一份掩码逻辑算就不会有这个偏差。
func (p *PrefixResolver) ProbeAddress() net.IP {
	ones, bits := p.prefix.Mask.Size()
	out := make(net.IP, net.IPv6len)
	copy(out, p.prefix.IP.To16())

	hostBits := bits - ones
	if hostBits == 0 {
		return out // /128，前缀里只有这一个地址
	}

	// 偏移量挑一个显眼的值，肉眼一看就知道是自检地址而不是真实业务地址。
	// 窄前缀放不下时按主机位截断；截成 0 就退回 1（网络地址本身在 IPv6
	// 里可用，但用它容易和"前缀本身"混淆，+1 更清楚）。
	var offset uint64 = 0x7ea30001
	if hostBits < 64 {
		offset &= (1 << uint(hostBits)) - 1
	}
	if offset == 0 {
		offset = 1
	}

	// 主机位此刻全为 0（ParseCIDR 保证），且 offset 不超过主机位能表示的范围，
	// 所以直接加进低 64 位不会向上进位污染前缀。
	low := binary.BigEndian.Uint64(out[8:])
	binary.BigEndian.PutUint64(out[8:], low+offset)
	return out
}

// DashForm 把地址写成用户名要求的破折号形态。
//
// 用户名里不能有冒号：RFC 7617 的 Basic 和 curl 的 --proxy-user 都按
// 第一个冒号拆 user:pass，带冒号的用户名会在发出前就被客户端切碎。
func DashForm(ip net.IP) string {
	return strings.ReplaceAll(ip.String(), ":", "-")
}

// RandomAddresses 在前缀内随机取 n 个地址，供批量生成代理串用。
//
// 随机而不是顺序（::1, ::2, ...）是有意的：顺序地址会让整段流量
// 在上游看来高度规律，而且一旦其中一个被标记，相邻的很容易被连坐。
// /56 里有 7.2e16 个地址，随机取几百个碰撞概率可以忽略。
func (p *PrefixResolver) RandomAddresses(n int) ([]net.IP, error) {
	if n <= 0 {
		return nil, fmt.Errorf("数量必须大于 0")
	}
	ones, bits := p.prefix.Mask.Size()
	hostBits := bits - ones
	if hostBits == 0 {
		// /128 里只有一个地址，要几个都只能给这一个。
		return nil, fmt.Errorf("前缀 %s 只包含一个地址，无法批量生成", p.prefix)
	}

	// 可用地址数远小于请求数时直接说清楚，而不是进循环里反复撞重复。
	if hostBits < 32 {
		if capacity := uint64(1) << uint(hostBits); uint64(n) > capacity/2 {
			return nil, fmt.Errorf("前缀 %s 只有 %d 个地址，一次最多生成 %d 个",
				p.prefix, capacity, capacity/2)
		}
	}

	base := p.prefix.IP.To16()
	seen := make(map[string]struct{}, n)
	out := make([]net.IP, 0, n)

	// 上限防死循环：极端情况下随机源退化也不至于把请求挂住。
	for attempts := 0; len(out) < n && attempts < n*100; attempts++ {
		ip := make(net.IP, net.IPv6len)
		copy(ip, base)

		// 只随机主机位，网络位保持不变——生成出前缀外的地址就等于
		// 生成了一个服务端自己会拒绝的地址。
		randomBits := make([]byte, net.IPv6len)
		if _, err := rand.Read(randomBits); err != nil {
			return nil, fmt.Errorf("生成随机数失败: %w", err)
		}
		for i := 0; i < net.IPv6len; i++ {
			// mask[i] 为 0 的位是主机位，可以随机；为 1 的是网络位，保持。
			hostMask := ^p.prefix.Mask[i]
			ip[i] = (base[i] & p.prefix.Mask[i]) | (randomBits[i] & hostMask)
		}

		// 跳过全零主机位（网络地址本身）和特殊用途地址。
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() || ip.Equal(base) {
			continue
		}
		key := ip.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}

	if len(out) < n {
		return nil, fmt.Errorf("只生成出 %d 个不重复地址（请求 %d 个），前缀可能太窄", len(out), n)
	}
	return out, nil
}
