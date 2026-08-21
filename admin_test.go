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

// ── 批量生成 ──

func TestAdmin_GenerateReturnsUsableProxyStrings(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")
	pass := proxy.Config().Password

	code, body := do(t, ts, "POST", "/api/generate", "adminpass123",
		map[string]any{"count": 5, "host": "example.net"})
	if code != http.StatusOK {
		t.Fatalf("生成失败: %d %v", code, body["error"])
	}
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) != 5 {
		t.Fatalf("条目数 = %v, 期望 5", body["entries"])
	}

	seen := make(map[string]bool)
	for i, raw := range entries {
		e := raw.(map[string]any)
		addr := e["address"].(string)
		user := e["user"].(string)
		socks := e["socks5"].(string)

		// 地址必须落在前缀内，否则服务端自己会拒绝——生成一堆不能用的串
		// 比报错更糟，用户要试到第一个失败才发现。
		ip := net.ParseIP(addr)
		if ip == nil || !proxy.resolver.prefix.Contains(ip) {
			t.Errorf("第 %d 条地址 %q 不在前缀内", i, addr)
		}
		// 用户名必须是破折号形态：带冒号会被 curl 按第一个冒号切碎。
		if strings.Contains(user, ":") {
			t.Errorf("第 %d 条用户名 %q 含冒号", i, user)
		}
		// 必须能被服务端自己的解析器接受——这是"生成的串真的能用"的硬证据。
		if _, err := proxy.resolver.Resolve(user); err != nil {
			t.Errorf("第 %d 条用户名 %q 服务端无法解析: %v", i, user, err)
		}
		if seen[addr] {
			t.Errorf("地址重复: %s", addr)
		}
		seen[addr] = true

		// socks5h 而非 socks5：h 表示域名交给代理解析。用 socks5 的话
		// 客户端先本地解析再发 IP，而白名单模式下服务端拒绝 IP 字面量目标。
		if !strings.HasPrefix(socks, "socks5h://") {
			t.Errorf("第 %d 条应该用 socks5h://（域名交给代理解析），得到 %q", i, socks)
		}
		if !strings.Contains(socks, pass) {
			t.Errorf("第 %d 条缺少口令", i)
		}
		if !strings.Contains(socks, "example.net") {
			t.Errorf("第 %d 条没用上指定的 host: %q", i, socks)
		}

		// 本机版：除了主机名换成 127.0.0.1，其余必须完全一致。
		// 服务端拼好再下发，而不是让前端拿公网串做字符串替换——
		// 口令里恰好含主机名或 @ 的话，替换会打在错误的位置上。
		socksLocal := e["socks5Local"].(string)
		httpLocal := e["httpLocal"].(string)
		wantSocks := "socks5h://" + user + ":" + pass + "@127.0.0.1:"
		if !strings.HasPrefix(socksLocal, wantSocks) {
			t.Errorf("第 %d 条本机版 socks5 不对: %q", i, socksLocal)
		}
		if !strings.HasPrefix(httpLocal, "http://"+user+":"+pass+"@127.0.0.1:") {
			t.Errorf("第 %d 条本机版 http 不对: %q", i, httpLocal)
		}
		// 端口必须和公网版一致：两个版本只该差主机名。
		if p1, p2 := portOf(socks), portOf(socksLocal); p1 != p2 {
			t.Errorf("第 %d 条公网版端口 %s 与本机版 %s 不一致", i, p1, p2)
		}
	}
}

// portOf 取代理串末尾的端口。
func portOf(proxyURL string) string {
	if idx := strings.LastIndex(proxyURL, ":"); idx >= 0 {
		return proxyURL[idx+1:]
	}
	return ""
}

// 口令里含主机名时，前端若用字符串替换生成本机版会替换到口令上去。
// 实测：host=1.2.3.4、口令 "my1.2.3.4pass"，朴素替换得到
//
//	socks5h://user:my127.0.0.1pass@1.2.3.4:6080
//
// ——口令被改了，主机名却没换。串看起来正常，用的时候才发现认证失败。
// 服务端分别拼接就没有这个问题，这条测试钉住它。
func TestAdmin_GenerateLocalWithTrickyPassword(t *testing.T) {
	proxy, _ := startTestServer(t, []string{"example.com"})
	// 口令里嵌着待会儿要传的 host，专门用来触发朴素替换的错误
	cfg := *proxy.Config()
	cfg.Password = "my1.2.3.4pass"
	proxy.cfg.Store(&cfg)

	admin := NewAdminServer(proxy, "adminpass123", "")
	ts := httptest.NewServer(admin.Handler())
	t.Cleanup(ts.Close)

	_, body := do(t, ts, "POST", "/api/generate", "adminpass123",
		map[string]any{"count": 1, "host": "1.2.3.4"})
	e := body["entries"].([]any)[0].(map[string]any)
	user := e["user"].(string)

	wantLocal := "socks5h://" + user + ":my1.2.3.4pass@127.0.0.1:" +
		portOf(e["socks5"].(string))
	if got := e["socks5Local"].(string); got != wantLocal {
		t.Errorf("含特殊字符的口令导致本机版拼错了\n得到: %s\n期望: %s", got, wantLocal)
	}
}

// 代理端口和管理面端口不是一回事。生成串时用错端口，
// 用户复制出去连的是管理面，得到一堆看不懂的 HTTP 报错。
func TestAdmin_GenerateUsesProxyPortNotAdminPort(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")
	// startTestServer 里 Listen 是 127.0.0.1:0，实际端口由内核分配
	wantPort := proxyPortFrom(proxy.Config().Listen)

	_, body := do(t, ts, "POST", "/api/generate", "adminpass123", map[string]any{"count": 1})
	if got := int(body["port"].(float64)); got != wantPort {
		t.Errorf("端口 = %d, 期望代理端口 %d", got, wantPort)
	}
}

func TestAdmin_GenerateRejectsAbsurdCount(t *testing.T) {
	_, _, ts := startAdmin(t, "")
	if code, _ := do(t, ts, "POST", "/api/generate", "adminpass123",
		map[string]any{"count": 100000}); code != http.StatusBadRequest {
		t.Errorf("超大数量应被拒，得到 %d", code)
	}
}

func TestAdmin_GenerateRequiresAuth(t *testing.T) {
	_, _, ts := startAdmin(t, "")
	if code, _ := do(t, ts, "POST", "/api/generate", "", map[string]any{"count": 1}); code != http.StatusUnauthorized {
		t.Errorf("未授权应 401，得到 %d", code)
	}
}

// ── 改管理口令 ──

func TestAdmin_ChangeAdminPassword(t *testing.T) {
	_, _, ts := startAdmin(t, "")

	code, body := do(t, ts, "PUT", "/api/admin-password", "adminpass123",
		map[string]any{"password": "brandnewadminpw123"})
	if code != http.StatusOK {
		t.Fatalf("改口令失败: %d %v", code, body["error"])
	}
	// 必须把新口令回给前端。不回的话前端本地还存着旧的，
	// 下一个请求就 401——操作明明成功了却被登出。
	if body["token"] != "brandnewadminpw123" {
		t.Errorf("应回传新口令供前端替换，得到 %v", body["token"])
	}

	if code, _ := do(t, ts, "GET", "/api/status", "adminpass123", nil); code != http.StatusUnauthorized {
		t.Errorf("旧口令应立即失效，得到 %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/status", "brandnewadminpw123", nil); code != http.StatusOK {
		t.Errorf("新口令应可用，得到 %d", code)
	}
}

// 两个口令相同会让服务下次启动时 log.Fatalf。放行的话这次还能跑，
// 下次重启就起不来，而且现场完全看不出是几天前那次改口令埋的。
func TestAdmin_RejectsPasswordCollision(t *testing.T) {
	_, proxy, ts := startAdmin(t, "")
	proxyPass := proxy.Config().Password

	// 把管理口令改成与代理口令相同 -> 拒绝
	if code, body := do(t, ts, "PUT", "/api/admin-password", "adminpass123",
		map[string]any{"password": proxyPass}); code != http.StatusBadRequest {
		t.Errorf("管理口令=代理口令 应被拒，得到 %d %v", code, body["error"])
	}
	// 反过来：把代理口令改成与管理口令相同 -> 也要拒绝
	if code, body := do(t, ts, "PUT", "/api/config", "adminpass123",
		map[string]any{"password": "adminpass123"}); code != http.StatusBadRequest {
		t.Errorf("代理口令=管理口令 应被拒，得到 %d %v", code, body["error"])
	}
}

func TestAdmin_AdminPasswordValidation(t *testing.T) {
	_, _, ts := startAdmin(t, "")
	for _, tc := range []struct{ name, pw string }{
		{"太短", "short"},
		{"刚好差一位", "elevenchars"},
		{"空", ""},
		{"含换行", "has\nnewline12345"},
	} {
		if code, _ := do(t, ts, "PUT", "/api/admin-password", "adminpass123",
			map[string]any{"password": tc.pw}); code != http.StatusBadRequest {
			t.Errorf("%s(%q): 应被拒，得到 %d", tc.name, tc.pw, code)
		}
	}
}

func TestAdmin_AdminPasswordPersists(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env")
	if err := os.WriteFile(envFile,
		[]byte("PROXY_ADMIN_PASSWORD=adminpass123\nPROXY_MAX_CONNS=99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, ts := startAdmin(t, envFile)

	if code, body := do(t, ts, "PUT", "/api/admin-password", "adminpass123",
		map[string]any{"password": "persistedadminpw"}); code != http.StatusOK {
		t.Fatalf("失败: %d %v", code, body["error"])
	}
	raw, _ := os.ReadFile(envFile)
	got := string(raw)
	if !strings.Contains(got, "PROXY_ADMIN_PASSWORD=persistedadminpw") {
		t.Errorf("新口令没写进文件:\n%s", got)
	}
	if strings.Contains(got, "adminpass123") {
		t.Errorf("旧口令还在:\n%s", got)
	}
	if !strings.Contains(got, "PROXY_MAX_CONNS=99") {
		t.Errorf("未知键被吃掉了:\n%s", got)
	}
}

// 改管理口令时一边有请求在读——atomic.Pointer 的正确性证明。
func TestAdmin_PasswordChangeIsRaceFree(t *testing.T) {
	_, _, ts := startAdmin(t, "")

	stop := make(chan struct{})
	var wg sync.WaitGroup
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
				// 口令一直在变，这里不断言状态码，只要不触发竞态检测即可
				do2(ts, "GET", "/api/status", "somepassword")
			}
		}()
	}
	for i := 0; i < 10; i++ {
		pw := fmt.Sprintf("rotatingadminpw%02d", i)
		prev := "adminpass123"
		if i > 0 {
			prev = fmt.Sprintf("rotatingadminpw%02d", i-1)
		}
		if code, _ := do(t, ts, "PUT", "/api/admin-password", prev,
			map[string]any{"password": pw}); code != http.StatusOK {
			t.Errorf("第 %d 次改口令失败: %d", i, code)
		}
	}
	close(stop)
	wg.Wait()
}

// do2 不带 *testing.T，供并发 goroutine 使用（t 的方法不是并发安全的）。
func do2(ts *httptest.Server, method, path, token string) {
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}
