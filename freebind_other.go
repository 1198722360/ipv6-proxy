//go:build !linux

package main

import "syscall"

// 非 Linux 平台没有 IPV6_FREEBIND。绑定本机未配置的地址会失败，
// 这个服务在这些平台上只能绑真实存在的地址——开发调试够用，生产不适用。
func setFreebind(network, address string, c syscall.RawConn) error {
	return nil
}

const freebindSupported = false
