package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 全部来自环境变量，没有配置文件——这个服务只有几个旋钮，
// 加一层文件解析只会多一处出错的地方。
type Config struct {
	// Listen 监听地址。默认 0.0.0.0:6080：外部机器要能连上，
	// 想收敛暴露面就改成 127.0.0.1 走 SSH 隧道。
	Listen string

	// Prefix 出口地址所属的 IPv6 前缀（CIDR）。留空 = 启动时自动探测。
	//
	// 它同时是安全边界：用户名里传来的地址必须落在这个前缀内，
	// 否则代理就成了"绑任意源地址"的工具，能伪造不属于本机的 IP 发包。
	Prefix string

	// Password 唯一的认证凭据。留空则启动时随机生成并打印到日志。
	Password string

	// AllowedHosts 允许 CONNECT 的目标白名单，逗号分隔；"*" = 不限制。
	//
	// 默认限定 OpenAI 相关域名。这是公网开放代理唯一的实质性缓解：
	// 密码是单一屏障，一旦泄漏，"不限目标"意味着别人能用你的 IP 访问任意目标，
	// 溯源指向你的服务器。限定之后即便泄漏，滥用价值也接近零。
	AllowedHosts []string

	// DialTimeout 连接上游的超时。
	DialTimeout time.Duration

	// IdleTimeout 空闲连接回收时间。取 rt 是短交互，宽松一点无妨。
	IdleTimeout time.Duration

	// MaxConns 同时在线连接上限，防止把文件描述符吃光。
	MaxConns int

	// AdminListen 管理面监听地址。留空 = 不启动管理面。
	//
	// 默认就是留空：管理面能改白名单，把它改成 "*" 等于把这台机器变成
	// 公网开放代理。这个能力必须由部署者显式开启，不能因为升级了个版本
	// 就凭空多出一个监听端口。
	AdminListen string

	// AdminPassword 管理面口令，**与 Password 相互独立**。
	//
	// 共用一个的话，在管理面上改代理口令的那一刻自己的会话就失效了，
	// 改到一半会把自己锁在外面。
	AdminPassword string

	// EnvFile 配置文件路径，用于持久化在线修改。留空 = 只改内存。
	EnvFile string
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		Listen:       envOr("PROXY_LISTEN", "0.0.0.0:6080"),
		Prefix:       os.Getenv("PROXY_IPV6_PREFIX"),
		Password:     os.Getenv("PROXY_PASSWORD"),
		AllowedHosts: splitHosts(envOr("PROXY_ALLOWED_HOSTS", "chatgpt.com,*.chatgpt.com,*.openai.com")),
		DialTimeout:  envDuration("PROXY_DIAL_TIMEOUT", 15*time.Second),
		IdleTimeout:  envDuration("PROXY_IDLE_TIMEOUT", 300*time.Second),
		MaxConns:     envInt("PROXY_MAX_CONNS", 256),

		AdminListen:   strings.TrimSpace(os.Getenv("PROXY_ADMIN_LISTEN")),
		AdminPassword: os.Getenv("PROXY_ADMIN_PASSWORD"),
		EnvFile:       envFilePath(),
	}
	if len(cfg.AllowedHosts) == 0 {
		return nil, fmt.Errorf("PROXY_ALLOWED_HOSTS 不能为空；不限制请显式写 '*'")
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	// 兼容裸秒数写法（"300"），运维习惯上比 "300s" 更常见。
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return fallback
}

func splitHosts(raw string) []string {
	var out []string
	for _, piece := range strings.Split(raw, ",") {
		if h := strings.ToLower(strings.TrimSpace(piece)); h != "" {
			out = append(out, h)
		}
	}
	return out
}
