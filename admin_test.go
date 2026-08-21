package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startAdmin 起一个管理面，挂在一个真实但用假拨号器的代理服务上。
func startAdmin(t *testing.T, envFile string) (*AdminServer, *Server, *httptest.Server) {
	t.Helper()
	proxy, _ := startTestServer(t, []string{"example.com"})
	admin := NewAdminServer(proxy, "adminpass123", envFile)
	ts := httptest.NewServer(admin.Handler())
	t.Cleanup(ts.Close)
	return admin, proxy, ts
}

func do(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAdmin_AuthRequired(t *testing.T) {
	_, _, ts := startAdmin(t, "")

	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"无凭据", "", http.StatusUnauthorized},
		{"错口令", "wrong", http.StatusUnauthorized},
		{"口令前缀", "adminpass", http.StatusUnauthorized},
		{"正确口令", "adminpass123", http.StatusOK},
	} {
		if code, _ := do(t, ts, "GET", "/api/status", tc.token, nil); code != tc.want {
			t.Errorf("%s: 状态码 = %d, 期望 %d", tc.name, code, tc.want)
		}
	}
}

// 管理面走明文 HTTP、且用户选择了公网可达。响应里带明文代理口令
// 等于每次刷新页面都在链路上广播一次凭据。
func TestAdmin_ConfigNeverLeaksPassword(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")
	secret := proxy.Config().Password
	if secret == "" {
		t.Fatal("测试前提不成立：代理口令为空")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/config", nil)
	req.Header.Set("Authorization", "Bearer adminpass123")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := readAllString(resp.Body)

	if strings.Contains(raw, secret) {
		t.Errorf("响应里出现了明文代理口令！\n响应: %s", raw)
	}
}

func TestAdmin_LoginRateLimit(t *testing.T) {
	_, _, ts := startAdmin(t, "")

	for i := 0; i < maxLoginFailures; i++ {
		if code, _ := do(t, ts, "POST", "/api/login", "", map[string]string{"password": "wrong"}); code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误登录: 状态码 = %d, 期望 401", i+1, code)
		}
	}
	// 达到阈值后，即使口令正确也应该被拦住——否则限速形同虚设。
	code, body := do(t, ts, "POST", "/api/login", "", map[string]string{"password": "adminpass123"})
	if code != http.StatusTooManyRequests {
		t.Errorf("锁定后用正确口令: 状态码 = %d, 期望 429（消息: %v）", code, body["error"])
	}
}

func TestAdmin_LoginSuccessResetsCounter(t *testing.T) {
	_, _, ts := startAdmin(t, "")
	// 失败几次但不到阈值，然后成功——计数器应该被清零。
	for i := 0; i < maxLoginFailures-1; i++ {
		do(t, ts, "POST", "/api/login", "", map[string]string{"password": "wrong"})
	}
	if code, _ := do(t, ts, "POST", "/api/login", "", map[string]string{"password": "adminpass123"}); code != http.StatusOK {
		t.Fatalf("未达阈值时正确口令应通过，得到 %d", code)
	}
	for i := 0; i < maxLoginFailures-1; i++ {
		do(t, ts, "POST", "/api/login", "", map[string]string{"password": "wrong"})
	}
	if code, _ := do(t, ts, "POST", "/api/login", "", map[string]string{"password": "adminpass123"}); code != http.StatusOK {
		t.Errorf("成功登录应重置失败计数，得到 %d", code)
	}
}

// 改白名单必须立刻对**下一个连接**生效，不需要重启。
func TestAdmin_HostsTakeEffectImmediately(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")

	// 改之前：newsite.com 不在白名单里，应被拒。
	c := dialProxy(t, proxy)
	if rep := socks5Handshake(t, c, "2604-2dc0-143-8200--1", "testpass", "newsite.com", 443); rep == repSuccess {
		t.Fatal("改配置前 newsite.com 就被放行了，测试前提不成立")
	}

	if code, body := do(t, ts, "PUT", "/api/config", "adminpass123",
		map[string]any{"allowedHosts": []string{"example.com", "newsite.com"}}); code != http.StatusOK {
		t.Fatalf("改白名单失败: %d %v", code, body["error"])
	}

	// 改之后：同一个进程、没有重启，新连接应该通过。
	c2 := dialProxy(t, proxy)
	if rep := socks5Handshake(t, c2, "2604-2dc0-143-8200--1", "testpass", "newsite.com", 443); rep != repSuccess {
		t.Errorf("改白名单后 newsite.com 仍被拒（应答 0x%02x）", rep)
	}
}

func TestAdmin_PasswordChangeTakesEffect(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")

	if code, body := do(t, ts, "PUT", "/api/config", "adminpass123",
		map[string]any{"password": "newproxypass"}); code != http.StatusOK {
		t.Fatalf("改代理口令失败: %d %v", code, body["error"])
	}

	c := dialProxy(t, proxy)
	if rep := socks5Handshake(t, c, "2604-2dc0-143-8200--1", "testpass", "example.com", 443); rep != 0xFE {
		t.Errorf("旧口令仍能通过（应答 0x%02x）", rep)
	}
	c2 := dialProxy(t, proxy)
	if rep := socks5Handshake(t, c2, "2604-2dc0-143-8200--1", "newproxypass", "example.com", 443); rep != repSuccess {
		t.Errorf("新口令无法通过（应答 0x%02x）", rep)
	}
}

// 非法输入必须被拒，且**不能落盘**——写了一半的坏配置会让服务下次起不来。
func TestAdmin_RejectsInvalidInputWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env")
	original := "PROXY_PASSWORD=originalpass\nPROXY_ALLOWED_HOSTS=example.com\n"
	if err := os.WriteFile(envFile, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, ts := startAdmin(t, envFile)

	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"空白名单", map[string]any{"allowedHosts": []string{}}},
		{"全是空白的白名单", map[string]any{"allowedHosts": []string{"  ", ""}}},
		{"白名单含逗号", map[string]any{"allowedHosts": []string{"a.com,b.com"}}},
		{"口令太短", map[string]any{"password": "short"}},
		{"口令含冒号", map[string]any{"password": "has:colon:here"}},
		{"什么都没改", map[string]any{}},
	} {
		if code, _ := do(t, ts, "PUT", "/api/config", "adminpass123", tc.body); code != http.StatusBadRequest {
			t.Errorf("%s: 状态码 = %d, 期望 400", tc.name, code)
		}
	}

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("非法输入不该改动配置文件。\n原始:\n%s\n现在:\n%s", original, got)
	}
}

func TestAdmin_PersistsToEnvFile(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env")
	if err := os.WriteFile(envFile,
		[]byte("# 用户手写的注释\nPROXY_PASSWORD=oldpass\nPROXY_MAX_CONNS=99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, ts := startAdmin(t, envFile)

	if code, body := do(t, ts, "PUT", "/api/config", "adminpass123", map[string]any{
		"allowedHosts": []string{"a.com", "*.b.com"},
		"password":     "brandnewpass",
	}); code != http.StatusOK {
		t.Fatalf("保存失败: %d %v", code, body["error"])
	}

	raw, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)

	for _, want := range []string{
		"PROXY_PASSWORD=brandnewpass",
		"PROXY_ALLOWED_HOSTS=a.com,*.b.com",
		"PROXY_MAX_CONNS=99", // 未知键必须保留
		"# 用户手写的注释",          // 注释必须保留
	} {
		if !strings.Contains(got, want) {
			t.Errorf("配置文件里缺少 %q\n实际内容:\n%s", want, got)
		}
	}
	if strings.Contains(got, "oldpass") {
		t.Errorf("旧口令没被替换掉:\n%s", got)
	}

	// 权限必须是 600：文件里有口令。
	info, err := os.Stat(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("权限 = %o, 期望 600", perm)
	}
}

// 未知路径必须回 404 而不是首页 HTML。
// 回 HTML 的话前端 JSON.parse 会报一个和真实原因毫无关系的错。
func TestAdmin_UnknownPathIs404(t *testing.T) {
	_, _, ts := startAdmin(t, "")
	resp, err := ts.Client().Get(ts.URL + "/api/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("未知路径状态码 = %d, 期望 404", resp.StatusCode)
	}
}

// 限速按来源 IP 独立计数：一个 IP 被锁不该影响别人。
func TestAdmin_RateLimitIsPerIP(t *testing.T) {
	l := newRateLimiter()
	for i := 0; i < maxLoginFailures; i++ {
		l.fail("1.1.1.1")
	}
	if locked, _ := l.locked("1.1.1.1"); !locked {
		t.Error("达到阈值的 IP 应被锁定")
	}
	if locked, _ := l.locked("2.2.2.2"); locked {
		t.Error("另一个 IP 不该被连坐")
	}
}

// X-Forwarded-For 是客户端可以随便填的。认它等于让攻击者
// 每次换一个假 IP 来绕过限速。
func TestAdmin_IgnoresForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIPFromRequest(r); got != "10.0.0.5" {
		t.Errorf("来源 IP = %q, 期望 10.0.0.5（不能采信 X-Forwarded-For）", got)
	}
}

// Step 1 的正确性证明：一边跑连接一边改配置，-race 下不能有竞态，
// 也不能因为原地改 map 而崩进程。
func TestAdmin_ConcurrentConfigChangeIsRaceFree(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 持续发起代理连接（读配置）
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := net.DialTimeout("tcp", proxy.Addr().String(), time.Second)
				if err != nil {
					continue
				}
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte{0x05, 0x01, 0x02})
				buf := make([]byte, 2)
				_, _ = c.Read(buf)
				_ = c.Close()
			}
		}()
	}

	// 同时反复改配置（写配置）
	for i := 0; i < 20; i++ {
		hosts := []string{"example.com", fmt.Sprintf("host%d.com", i)}
		if code, _ := do(t, ts, "PUT", "/api/config", "adminpass123",
			map[string]any{"allowedHosts": hosts}); code != http.StatusOK {
			t.Errorf("第 %d 次改配置失败: %d", i, code)
		}
	}

	close(stop)
	wg.Wait()
}

func readAllString(r interface{ Read([]byte) (int, error) }) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String(), nil
		}
	}
}
