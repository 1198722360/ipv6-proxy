//go:build linux

package main

import (
	"context"
	"net"
	"testing"
)

// 这个用例是整个"能否在无特权容器里运行"结论的实证。
// 它绑定一个本机绝不可能配置的地址：能成功就说明 FREEBIND 生效，
// 失败则说明该环境下必须回退到 ip_nonlocal_bind sysctl。
func TestFreebind_BindsUnconfiguredAddress(t *testing.T) {
	if !freebindSupported {
		t.Skip("本平台不支持 FREEBIND")
	}
	// 文档示例前缀（RFC 3849），本机绝无可能配置了它。
	addr := net.ParseIP("2001:db8:dead:beef::1")
	if err := bindOnly(addr); err != nil {
		t.Fatalf("FREEBIND 未生效，绑定未配置地址失败: %v\n"+
			"这意味着该环境必须设置 net.ipv6.ip_nonlocal_bind=1", err)
	}
}

// 对照组：关掉 FREEBIND 应当失败。若这个也成功，说明环境本身
// 已经开了 ip_nonlocal_bind，上面那个用例就失去了证明力。
func TestFreebind_WithoutOptionFails(t *testing.T) {
	lc := net.ListenConfig{} // 不设 Control
	conn, err := lc.Listen(context.Background(), "tcp6", "[2001:db8:dead:beef::2]:0")
	if err == nil {
		_ = conn.Close()
		t.Skip("环境已开启 ip_nonlocal_bind，无法构造对照组")
	}
	t.Logf("对照组如预期失败: %v", err)
}
