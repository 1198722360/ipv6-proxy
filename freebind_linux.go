//go:build linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setFreebind 打开 IPV6_FREEBIND，让 bind() 接受本机未配置的地址。
//
// 这是 per-socket 选项，**不需要 root、不需要任何 capability、
// 不需要改 sysctl**。它替代了 net.ipv6.ip_nonlocal_bind=1 那条宿主配置，
// 是这个服务能在普通容器里跑起来的关键。
//
// 值 78 = IPV6_FREEBIND（Linux 4.15+）。golang.org/x/sys 里没有这个常量，
// 所以直接写数值。内核不认时会返回 ENOPROTOOPT，此时回退到不带该选项，
// 让 bind 自己去报真正的错误——比在这里提前失败更好排查。
func setFreebind(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, ipv6Freebind, 1); e != nil {
			if e == unix.ENOPROTOOPT {
				return // 老内核，静默跳过
			}
			setErr = e
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

const ipv6Freebind = 78

// freebindSupported 供启动日志使用。
const freebindSupported = true
