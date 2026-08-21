package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed admin.html
var adminAssets embed.FS

const (
	// 登录限速。管理面能改白名单，改成 "*" 就等于把这台机器变成公网开放代理，
	// 所以这个口令端点的价值对攻击者很高。公网上的口令端点会在几小时内被扫到，
	// 限速不是可选项。
	maxLoginFailures = 5
	lockoutDuration  = 5 * time.Minute
)

// AdminServer 是管理面。**独立监听一个端口**，不与代理端口复用。
//
// 复用代理端口是不行的：那边靠首字节嗅探分流（0x05 走 SOCKS5，其余走
// CONNECT 处理器），在上面挂 HTTP 面会让未认证的请求进入已认证的代理路径。
type AdminServer struct {
	proxy *Server
	// password 是管理口令，可在运行期修改，所以用原子指针而不是裸 string。
	// string 是两字长，撕裂读会读到长度和数据不匹配的值——而这个字段
	// 每个请求都要读（checkAuth），改的时候正好有请求在读是常态。
	password atomic.Pointer[string]
	envFile  string

	limiter  *rateLimiter
	listener net.Listener
}

func NewAdminServer(proxy *Server, password, envFile string) *AdminServer {
	a := &AdminServer{
		proxy:   proxy,
		envFile: envFile,
		limiter: newRateLimiter(),
	}
	a.password.Store(&password)
	return a
}

// Password 返回当前管理口令。
func (a *AdminServer) Password() string { return *a.password.Load() }

func (a *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("GET /api/status", a.requireAuth(a.handleStatus))
	mux.HandleFunc("GET /api/config", a.requireAuth(a.handleGetConfig))
	mux.HandleFunc("PUT /api/config", a.requireAuth(a.handlePutConfig))
	mux.HandleFunc("PUT /api/admin-password", a.requireAuth(a.handlePutAdminPassword))
	mux.HandleFunc("POST /api/generate", a.requireAuth(a.handleGenerate))
	return mux
}

func (a *AdminServer) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("管理面监听 %s 失败: %w", addr, err)
	}
	a.listener = ln
	log.Printf("管理面 http://%s", ln.Addr())
	return a.Serve(ln)
}

// Serve 与 ListenAndServe 分开，让测试能先拿到已绑定的 listener
// （端口 0 要绑定后才知道实际端口）。与 Server.serveLoop 的拆分同理。
func (a *AdminServer) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler: a.Handler(),
		// 管理面在公网上，给读写都设上超时，避免慢速连接把 fd 占住。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return srv.Serve(ln)
}

func (a *AdminServer) Close() error {
	if a.listener != nil {
		return a.listener.Close()
	}
	return nil
}

// requireAuth 包一层鉴权。每个受保护的处理器都要显式套上——
// 与 team-pool 后端 requireAdmin 的写法一致。
func (a *AdminServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.checkAuth(r) {
			writeJSONError(w, http.StatusUnauthorized, "未授权")
			return
		}
		next(w, r)
	}
}

func (a *AdminServer) checkAuth(r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	token := strings.TrimSpace(header[len(prefix):])
	// 定长比较：逐字节短路比较会通过响应时间泄漏口令前缀。
	return subtle.ConstantTimeCompare([]byte(token), []byte(a.Password())) == 1
}

func (a *AdminServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// ServeMux 的 "GET /" 是通配，任何未匹配的路径都会落到这里。
	// 对未知路径回 404 而不是首页，否则 /api/typo 会返回一坨 HTML，
	// 前端拿去 JSON.parse 得到的报错和真实原因毫无关系。
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := adminAssets.ReadFile("admin.html")
	if err != nil {
		http.Error(w, "页面缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (a *AdminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIPFromRequest(r)
	if locked, until := a.limiter.locked(ip); locked {
		writeJSONError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试次数过多，请在 %d 秒后重试", int(time.Until(until).Seconds())+1))
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(a.Password())) != 1 {
		a.limiter.fail(ip)
		log.Printf("管理面登录失败，来源 %s", ip)
		writeJSONError(w, http.StatusUnauthorized, "口令错误")
		return
	}

	a.limiter.reset(ip)
	// 回显口令当令牌，与 team-pool 的 AuthController.login 同形态：
	// 没有会话状态，前端把它存起来后续每个请求带上。
	writeJSON(w, http.StatusOK, map[string]string{"token": a.Password()})
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := a.proxy.stats.Snapshot(a.proxy.active.Load())
	writeJSON(w, http.StatusOK, snap)
}

func (a *AdminServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.proxy.Config()
	// 绝不回明文口令。管理面在公网上、走明文 HTTP，
	// 把代理口令放进响应等于每次刷新页面都在链路上广播一次。
	writeJSON(w, http.StatusOK, map[string]any{
		"allowedHosts":   cfg.AllowedHosts,
		"passwordLength": len(cfg.Password),
		"prefix":         a.proxy.resolver.String(),
		"listen":         cfg.Listen,
		"maxConns":       cfg.MaxConns,
		"persistent":     a.envFile != "",
	})
}

func (a *AdminServer) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AllowedHosts []string `json:"allowedHosts"`
		Password     string   `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	old := a.proxy.Config()
	next := *old // 值拷贝：新配置整体替换旧的，绝不原地改
	updates := make(map[string]string)

	if req.AllowedHosts != nil {
		hosts, err := normalizeHosts(req.AllowedHosts)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		next.AllowedHosts = hosts
		updates["PROXY_ALLOWED_HOSTS"] = strings.Join(hosts, ",")
	}

	if req.Password != "" {
		if err := validateProxyPassword(req.Password); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// 不能把代理口令改成和管理口令一样。启动时 main.go 会因为两者
		// 相同而 log.Fatalf——也就是说这里放行的话，服务这次还能跑，
		// 下次重启就起不来了，而且现场看不出是几天前那次改口令埋的。
		if req.Password == a.Password() {
			writeJSONError(w, http.StatusBadRequest, "代理口令不能与管理口令相同（否则服务下次重启会拒绝启动）")
			return
		}
		next.Password = req.Password
		updates["PROXY_PASSWORD"] = req.Password
	}

	if len(updates) == 0 {
		writeJSONError(w, http.StatusBadRequest, "没有要修改的内容")
		return
	}

	// 先落盘再切内存。反过来的话，写盘失败时内存已经改了，
	// 页面显示"成功"，重启后却变回去——这种不一致比直接报错难查得多。
	if a.envFile != "" {
		if err := UpdateEnvFile(a.envFile, updates); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "持久化失败: "+err.Error())
			return
		}
	}

	// 写时复制：构造全新的 Policy 再整体换掉。
	// 原地改 Policy.exact 那个 map 会让正在读它的连接协程撞上
	// concurrent map read and map write，那是 runtime 直接打死进程。
	if req.AllowedHosts != nil {
		newPolicy := NewPolicy(next.AllowedHosts)
		// lookup 必须继承：测试会注入假 DNS，重建时丢掉它整套测试就废了。
		newPolicy.lookup = a.proxy.Policy().lookup
		a.proxy.policy.Store(newPolicy)
	}
	a.proxy.cfg.Store(&next)

	log.Printf("管理面更新配置: %s", strings.Join(sortedKeys(updates), ", "))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"persistent": a.envFile != "",
	})
}

// handleGenerate 批量生成代理串，供页面上一键复制。
//
// 出口地址是随机取的，不是 ::1 ::2 顺序排——顺序地址在上游看来高度规律，
// 而且一个被标记时相邻的容易被连坐。
func (a *AdminServer) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Count  int    `json:"count"`
		Format string `json:"format"` // socks5 / http / both
		Host   string `json:"host"`   // 客户端要连的地址；空则用请求里的 Host
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if req.Count <= 0 {
		req.Count = 10
	}
	// 上限防一次要几十万条把内存和页面都撑爆。
	if req.Count > 1000 {
		writeJSONError(w, http.StatusBadRequest, "一次最多生成 1000 条")
		return
	}

	cfg := a.proxy.Config()

	// 客户端要连的主机名。优先用调用方指定的；没指定就从浏览器访问
	// 管理面用的那个 Host 推——那个地址一定是从外部能连到本机的，
	// 比服务端自己 guess 一个可靠。
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = hostFromRequest(r)
	}
	// 代理端口和管理面端口不是同一个，必须从代理的监听地址里取。
	port := proxyPortFrom(cfg.Listen)

	addrs, err := a.proxy.resolver.RandomAddresses(req.Count)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	type entry struct {
		Address string `json:"address"`
		User    string `json:"user"`
		Socks5  string `json:"socks5"`
		HTTP    string `json:"http"`
		// 本机版：主机名固定 127.0.0.1，其余完全一致。
		// 给服务器上直接跑的程序、或 ssh -L 隧道用。
		Socks5Local string `json:"socks5Local"`
		HTTPLocal   string `json:"httpLocal"`
	}
	out := make([]entry, 0, len(addrs))
	portStr := strconv.Itoa(port)
	hp := net.JoinHostPort(host, portStr)
	// 本机串在服务端拼好，不让前端拿公网串去做字符串替换：
	// 口令里要是恰好含主机名或 @，替换会打在错误的位置上，
	// 而生成的串看起来还挺像那么回事，用的时候才发现连不上。
	hpLocal := net.JoinHostPort("127.0.0.1", portStr)
	for _, ip := range addrs {
		user := DashForm(ip)
		out = append(out, entry{
			Address: ip.String(),
			User:    user,
			// socks5h 而不是 socks5：h 表示域名交给代理去解析。
			// 用 socks5 的话客户端会先本地解析再把 IP 发过来，
			// 而服务端在白名单模式下拒绝 IP 字面量目标，整个请求会失败。
			Socks5:      fmt.Sprintf("socks5h://%s:%s@%s", user, cfg.Password, hp),
			HTTP:        fmt.Sprintf("http://%s:%s@%s", user, cfg.Password, hp),
			Socks5Local: fmt.Sprintf("socks5h://%s:%s@%s", user, cfg.Password, hpLocal),
			HTTPLocal:   fmt.Sprintf("http://%s:%s@%s", user, cfg.Password, hpLocal),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(out),
		"host":    host,
		"port":    port,
		"entries": out,
	})
}

// hostFromRequest 从请求的 Host 头里取主机名（去掉端口）。
//
// 用它是因为：浏览器能访问到管理面，说明这个地址从外部可达，
// 拿它当代理地址比服务端自己猜（监听 0.0.0.0 时根本猜不出）可靠。
func hostFromRequest(r *http.Request) string {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// proxyPortFrom 从监听地址里取端口。
func proxyPortFrom(listen string) int {
	if _, portStr, err := net.SplitHostPort(listen); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			return p
		}
	}
	return 6080
}

// handlePutAdminPassword 改管理口令。
//
// 单独一个端点而不是并进 /api/config，因为它的语义不一样：
// 改完当前这个 token 立刻失效，前端必须换用新口令重新存。
// 混在配置接口里会让"改了白名单顺手把自己踢下线"变得很容易发生。
func (a *AdminServer) handlePutAdminPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if err := validateAdminPassword(req.Password); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 与代理口令相同会让服务下次重启失败（main.go 里是 log.Fatalf）。
	if req.Password == a.proxy.Config().Password {
		writeJSONError(w, http.StatusBadRequest, "管理口令不能与代理口令相同（否则服务下次重启会拒绝启动）")
		return
	}

	// 先落盘再切内存：写盘失败时如果内存已经改了，页面显示成功、
	// 重启却变回旧口令，用户会拿着新口令死活登不进去。
	if a.envFile != "" {
		if err := UpdateEnvFile(a.envFile, map[string]string{
			"PROXY_ADMIN_PASSWORD": req.Password,
		}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "持久化失败: "+err.Error())
			return
		}
	}
	a.password.Store(&req.Password)

	// 改完之后旧 token 立即失效。把新口令回给前端，让它替换本地存的那份，
	// 否则用户下一个请求就被登出了——明明操作是成功的。
	log.Printf("管理面口令已修改")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      req.Password,
		"persistent": a.envFile != "",
	})
}

// validateAdminPassword 校验管理口令。
//
// 比代理口令严一档（12 位起）：管理面能改白名单，改成 * 就等于把这台
// 机器变成公网开放代理，而它还挂在公网上走明文 HTTP。
func validateAdminPassword(pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("管理口令至少 12 位（它能改白名单，比代理口令更值得保护）")
	}
	if strings.ContainsAny(pw, "\n\r") {
		return fmt.Errorf("口令不能含换行")
	}
	// 冒号本身在 Bearer 里没问题，但配置文件是 KEY=VALUE 逐行格式，
	// 换行会把文件结构破坏掉。冒号放行。
	return nil
}

// normalizeHosts 清洗白名单。
func normalizeHosts(raw []string) ([]string, error) {
	var out []string
	for _, h := range raw {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		// 逗号是 env 文件里的分隔符。放进一个条目里会让写出去的配置
		// 在下次启动时被拆成两条，得到和页面上看到的不一样的结果。
		if strings.ContainsAny(h, ", \t\n") {
			return nil, fmt.Errorf("白名单条目不能含逗号或空白: %q", h)
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		// 空白名单会被 LoadConfig 拒绝，服务下次就起不来了。
		return nil, fmt.Errorf("白名单不能为空；不限制请显式填 *")
	}
	return out, nil
}

// validateProxyPassword 校验代理口令。
func validateProxyPassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("口令至少 8 位")
	}
	// 冒号在 HTTP Basic 里是 user:pass 的分隔符，含冒号的口令
	// 会在 CONNECT 那条路径上被切错位置。
	if strings.ContainsAny(pw, ":\n\r") {
		return fmt.Errorf("口令不能含冒号或换行")
	}
	return nil
}

// rateLimiter 按来源 IP 记登录失败次数。
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	failures int
	until    time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: make(map[string]*limitEntry)}
}

func (l *rateLimiter) locked(ip string) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return false, time.Time{}
	}
	if time.Now().Before(e.until) {
		return true, e.until
	}
	return false, time.Time{}
}

func (l *rateLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		e = &limitEntry{}
		l.entries[ip] = e
	}
	e.failures++
	if e.failures >= maxLoginFailures {
		e.until = time.Now().Add(lockoutDuration)
		e.failures = 0
	}
}

func (l *rateLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// clientIPFromRequest 取来源 IP。
//
// 刻意**不看** X-Forwarded-For：那个头是客户端可以随便填的，
// 认它等于让攻击者每次换一个假 IP 来绕过限速。
// 如果将来真放在反向代理后面，要改成只信任已知代理传来的值。
func clientIPFromRequest(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
