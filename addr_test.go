package main

import (
	"strings"
	"testing"
)

func TestPrefixResolver_Resolve(t *testing.T) {
	r, err := NewPrefixResolver("2604:2dc0:143:8200::/56")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}

	ok := []string{
		"2604-2dc0-143-8200--1",
		"2604-2dc0-143-82ff-dead-beef-1-2", // /56 内的另一个 /64
		"2604-2dc0-143-8201--5%eth0",       // 带 zone 后缀
	}
	for _, s := range ok {
		if _, err := r.Resolve(s); err != nil {
			t.Errorf("应接受 %q，却报错: %v", s, err)
		}
	}

	bad := []string{
		"",
		"not-an-ip",
		"1.2.3.4",               // v4
		"2604-2dc0-143-8300--1", // 超出 /56
		"2001-db8--1",           // 完全不同的前缀
		"--1",                   // 回环
		"fe80--1",               // 链路本地
		"--",                    // 未指定
	}
	for _, s := range bad {
		if _, err := r.Resolve(s); err == nil {
			t.Errorf("应拒绝 %q，却通过了", s)
		}
	}
}

func TestPrefixResolver_BadConfig(t *testing.T) {
	bad := []string{"garbage", "10.0.0.0/8", "2604:2dc0::/8", "2604:2dc0::"}
	for _, s := range bad {
		if _, err := NewPrefixResolver(s); err == nil {
			t.Errorf("应拒绝前缀配置 %q", s)
		}
	}
}

func TestPrefixResolver_HostBitsCleared(t *testing.T) {
	// 前缀写成带主机位的形态时，包含性判断仍须按网络位算。
	// （Java 版这里出过 bug：手写的主机位清除是个自我拷贝空操作。）
	r, err := NewPrefixResolver("2604:2dc0:143:82ab:cdef::1/56")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if _, err := r.Resolve("2604-2dc0-143-8200--9"); err != nil {
		t.Errorf("主机位应被清除，同 /56 内地址应放行: %v", err)
	}
}

func TestPrefixResolver_DashForm(t *testing.T) {
	r, err := NewPrefixResolver("2604:2dc0:143:8200::/56")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	// 破折号形态是唯一支持的写法，翻译结果必须精确。
	cases := map[string]string{
		"2604-2dc0-143-8200--1":    "2604:2dc0:143:8200::1",
		"2604-2dc0-143-82ff--dead": "2604:2dc0:143:82ff::dead",
	}
	for in, want := range cases {
		ip, err := r.Resolve(in)
		if err != nil {
			t.Errorf("%q 应被接受: %v", in, err)
			continue
		}
		if ip.String() != want {
			t.Errorf("%q -> %s, 期望 %s", in, ip, want)
		}
	}
	if _, err := r.Resolve("2001-db8--1"); err == nil {
		t.Error("越界的破折号形态地址应被拒绝")
	}
}

// 冒号形态必须被明确拒绝。凭据里的冒号是分隔符：curl 的 --proxy-user
// 和 RFC 7617 都按第一个冒号拆，含冒号的用户名在发出前就被切碎了，
// 服务端只能猜哪段是地址哪段是口令。格式上排除冒号，歧义就不存在。
func TestPrefixResolver_RejectsColonForm(t *testing.T) {
	r, err := NewPrefixResolver("2604:2dc0:143:8200::/56")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	// 这些地址本身合法且在前缀内，被拒纯粹因为写法带冒号或方括号。
	for _, s := range []string{
		"2604:2dc0:143:8200::1",
		"[2604-2dc0-143-8200--1]",
		"[2604:2dc0:143:8200::1]",
	} {
		if _, err := r.Resolve(s); err == nil {
			t.Errorf("应拒绝 %q", s)
		}
	}
}

// 自检地址必须落在前缀内，且必须能通过 Resolve——部署脚本拿它做端到端验证，
// 算错了会让一套配置正常的部署显示成失败。窄前缀是这里唯一的难点：
// 脚本里字符串拼接的老写法对 /56 正确、对 /120 会溢出到前缀外。
func TestProbeAddress_InsidePrefixAcrossWidths(t *testing.T) {
	for _, cidr := range []string{
		"2604:2dc0:143:8200::/56",
		"2a01:4f8:c17:b8f::/64",
		"2001:db8::/32",
		"2a01:4f8:c17:b8f::/112",
		"2a01:4f8:c17:b8f::/120",
		"2a01:4f8:c17:b8f::/127",
		"2a01:4f8:c17:b8f::1/128",
	} {
		r, err := NewPrefixResolver(cidr)
		if err != nil {
			t.Fatalf("%s: 前缀解析失败: %v", cidr, err)
		}
		probe := r.ProbeAddress()
		if !r.prefix.Contains(probe) {
			t.Errorf("%s: 自检地址 %s 落在前缀外", cidr, probe)
		}
		// 破折号形态必须被 Resolve 接受——这正是部署脚本的用法。
		if _, err := r.Resolve(DashForm(probe)); err != nil {
			t.Errorf("%s: 自检地址 %s 无法通过 Resolve: %v", cidr, probe, err)
		}
	}
}

func TestDashForm_NoColon(t *testing.T) {
	r, err := NewPrefixResolver("2604:2dc0:143:8200::/56")
	if err != nil {
		t.Fatal(err)
	}
	got := DashForm(r.ProbeAddress())
	if strings.ContainsAny(got, ":") {
		t.Errorf("破折号形态里不能有冒号，得到 %q", got)
	}
	// 反向：转回去必须还是同一个地址。
	back, err := r.Resolve(got)
	if err != nil {
		t.Fatalf("破折号形态 %q 无法解析回地址: %v", got, err)
	}
	if !back.Equal(r.ProbeAddress()) {
		t.Errorf("往返不一致: %s -> %q -> %s", r.ProbeAddress(), got, back)
	}
}
