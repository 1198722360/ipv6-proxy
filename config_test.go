package main

import (
	"testing"
	"time"
)

func TestEnvDuration(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      time.Duration
	}{
		{"Go 时长语法", "45s", 45 * time.Second},
		{"分钟", "2m", 2 * time.Minute},
		{"裸秒数（运维习惯写法）", "300", 300 * time.Second},
		{"空值取默认", "", 15 * time.Second},
		{"非法值取默认", "abc", 15 * time.Second},
		{"零值取默认", "0", 15 * time.Second},
		{"负值取默认", "-5s", 15 * time.Second},
	} {
		t.Setenv("TEST_DURATION", tc.raw)
		if got := envDuration("TEST_DURATION", 15*time.Second); got != tc.want {
			t.Errorf("%s: envDuration(%q) = %v, 期望 %v", tc.name, tc.raw, got, tc.want)
		}
	}
}

func TestEnvInt(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"42", 42},
		{"", 256},
		{"abc", 256},
		{"0", 256},  // 0 个连接的服务没有意义，取默认
		{"-1", 256}, // 同上
		{" 7 ", 7},  // 两端空白应被容忍
	} {
		t.Setenv("TEST_INT", tc.raw)
		if got := envInt("TEST_INT", 256); got != tc.want {
			t.Errorf("envInt(%q) = %d, 期望 %d", tc.raw, got, tc.want)
		}
	}
}

func TestSplitHosts(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"a.com,b.com", []string{"a.com", "b.com"}},
		{" a.com , b.com ", []string{"a.com", "b.com"}},
		{"A.COM", []string{"a.com"}}, // 统一小写，否则大小写不同的写法匹配不上
		{"a.com,,b.com", []string{"a.com", "b.com"}},
		{"", nil},
		{" , ", nil},
	} {
		got := splitHosts(tc.raw)
		if len(got) != len(tc.want) {
			t.Errorf("splitHosts(%q) = %v, 期望 %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitHosts(%q) = %v, 期望 %v", tc.raw, got, tc.want)
				break
			}
		}
	}
}

// 空白名单必须让启动失败。静默降级成"什么都放行"是最糟的失败方式：
// 一个本该定向的代理会在无人察觉的情况下变成公网开放代理。
func TestLoadConfig_RejectsEmptyAllowedHosts(t *testing.T) {
	t.Setenv("PROXY_ALLOWED_HOSTS", " , ")
	if _, err := LoadConfig(); err == nil {
		t.Error("白名单为空时应报错")
	}
}

func TestIsPublicListen(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:6081", false},
		{"[::1]:6081", false},
		{"0.0.0.0:6081", true},
		{"1.2.3.4:6081", true},
		{":6081", true},   // 等价于所有网卡
		{"garbage", true}, // 判断不了就当公网，宁可多提醒
	} {
		if got := isPublicListen(tc.addr); got != tc.want {
			t.Errorf("isPublicListen(%q) = %v, 期望 %v", tc.addr, got, tc.want)
		}
	}
}
