package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// version 由 build.sh 用 -ldflags "-X main.version=..." 注入。
// 默认 "dev" 表示这是直接 go build 出来的、没走构建脚本的二进制。
//
// 部署脚本靠 `ipv6-proxy --version` 做两件事：确认新二进制确实覆盖上去了
// （systemd restart 成功不等于文件换了），以及在 install 之前试跑一次、
// 用它是否能执行来判断架构对不对——比 file(1) 可靠，那个命令未必装了。
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version", "version":
			fmt.Println(version)
			return
		case "probe-addr":
			// 部署脚本用它算自检地址。放在 Go 里而不是 shell 里，
			// 是为了让"前缀内的地址"这件事由同一份掩码逻辑决定——
			// shell 拼字符串在窄前缀（如 /120）下会算到前缀外面去。
			//
			// 输出两行：第一行冒号形态（给 ip route get 用），
			// 第二行破折号形态（给 --proxy-user 用）。
			if err := printProbeAddr(); err != nil {
				log.Fatalf("%v", err)
			}
			return
		default:
			// 本服务只认环境变量。默默忽略未知参数会让 "改了启动参数但没生效"
			// 变成一个查半天的问题，不如直接报错。
			log.Fatalf("未知参数 %q；本服务只通过环境变量配置（仅 --version 例外）", os.Args[1])
		}
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[ipv6-proxy] ")

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	resolver, err := NewPrefixResolver(cfg.Prefix)
	if err != nil {
		log.Fatalf("出口前缀不可用: %v", err)
	}

	if cfg.Password == "" {
		cfg.Password = randomPassword()
		log.Printf("未设置 PROXY_PASSWORD，本次随机生成: %s", cfg.Password)
		log.Printf("注意：重启会重新生成。要固定请设置 PROXY_PASSWORD 环境变量。")
	}

	policy := NewPolicy(cfg.AllowedHosts)

	log.Printf("版本: %s", version)
	log.Printf("出口前缀: %s", resolver)
	if len(cfg.AllowedHosts) == 1 && cfg.AllowedHosts[0] == "*" {
		log.Printf("目标白名单: 不限制（仅内网拦截生效）")
	} else {
		log.Printf("目标白名单: %v", cfg.AllowedHosts)
	}
	log.Printf("最大连接数: %d, 拨号超时: %s, 空闲超时: %s", cfg.MaxConns, cfg.DialTimeout, cfg.IdleTimeout)
	if freebindSupported {
		log.Printf("IPV6_FREEBIND: 已启用（无需 ip_nonlocal_bind sysctl）")
	} else {
		log.Printf("IPV6_FREEBIND: 本平台不支持，只能绑定本机已配置的地址")
	}

	srv := NewServer(cfg, policy, resolver)

	// 管理面默认开启。它能改白名单，也就意味着能把这个定向代理变成
	// 公网开放代理，所以下面三道闸一个都不能省：口令必填、与代理口令
	// 强制分离、登录限速（在 admin.go 里）。
	if cfg.AdminListen != "" {
		if cfg.AdminPassword == "" {
			cfg.AdminPassword = randomPassword()
			log.Printf("未设置 PROXY_ADMIN_PASSWORD，本次随机生成: %s", cfg.AdminPassword)
			log.Printf("注意：重启会重新生成。要固定请写进配置文件。")
		}
		if cfg.AdminPassword == cfg.Password {
			// 共用口令时，在管理面改代理口令会把自己踢下线。
			log.Fatalf("PROXY_ADMIN_PASSWORD 不能与 PROXY_PASSWORD 相同")
		}
		if cfg.EnvFile == "" {
			log.Printf("警告：未设置 PROXY_ENV_FILE，管理面的修改重启后会丢失")
		}
		admin := NewAdminServer(srv, cfg.AdminPassword, cfg.EnvFile)
		if isPublicListen(cfg.AdminListen) {
			// 默认开启意味着升级一次就会凭空多出一个公网端口。
			// 这件事必须在日志里说清楚，不能让人是被扫到了才发现。
			log.Printf("警告：管理面监听在 %s（公网可达），走的是明文 HTTP。", cfg.AdminListen)
			log.Printf("      口令可被链路上的中间人嗅探，且管理面能改白名单——")
			log.Printf("      改成 * 等于把这台机器变成公网开放代理。")
			log.Printf("      建议：防火墙限定来源 IP，或设 PROXY_ADMIN_LISTEN=127.0.0.1:6081 走 SSH 隧道。")
			log.Printf("      不需要管理面就设 PROXY_ADMIN_LISTEN=off。")
		}
		go func() {
			if err := admin.ListenAndServe(cfg.AdminListen); err != nil {
				// 管理面起不来（端口被占等）不该让代理跟着死——
				// 代理才是主业，管理面只是附属。
				log.Printf("管理面退出: %v（代理服务不受影响）", err)
			}
		}()
	} else {
		log.Printf("管理面已关闭（PROXY_ADMIN_LISTEN=off）")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("收到退出信号，停止接受新连接")
		_ = srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
	log.Printf("已退出")
}

// isPublicListen 判断监听地址是否对外可达。
// 只用于是否打印警告，判断保守一些无妨——多提醒一次不会有害。
func isPublicListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" {
		return true // ":6081" 等价于所有网卡
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func randomPassword() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("生成随机口令失败: %v", err)
	}
	return hex.EncodeToString(buf)
}

// printProbeAddr 供部署脚本调用：读 PROXY_IPV6_PREFIX，打印前缀内的自检地址。
func printProbeAddr() error {
	resolver, err := NewPrefixResolver(os.Getenv("PROXY_IPV6_PREFIX"))
	if err != nil {
		return err
	}
	probe := resolver.ProbeAddress()
	// 自检地址必须真能通过 Resolve，否则脚本会拿一个服务端拒绝的地址去测，
	// 得到"部署失败"的假象。这里当场验一遍，不合格就报错而不是输出。
	if _, err := resolver.Resolve(DashForm(probe)); err != nil {
		return fmt.Errorf("自检地址 %s 无法通过校验: %w", probe, err)
	}
	fmt.Println(probe.String())
	fmt.Println(DashForm(probe))
	return nil
}
