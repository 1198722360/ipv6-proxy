#!/usr/bin/env bash
#
# 交叉编译出 Linux 静态二进制。在 macOS / Linux / 任何有 Go 的机器上都能跑。
#
# 用法：
#   ./build.sh                 # 编译 linux/amd64（绝大多数 VPS）
#   ./build.sh arm64           # 编译 linux/arm64（甲骨文 ARM、树莓派等）
#   ./build.sh amd64 arm64     # 两个都编
#
# 产物在 dist/ipv6-proxy-linux-<arch>。

set -euo pipefail
cd "$(dirname "$0")"

ARCHS=("$@")
[ ${#ARCHS[@]} -eq 0 ] && ARCHS=(amd64)

command -v go >/dev/null 2>&1 || {
    echo "找不到 go。装一个：https://go.dev/dl/  （或 apt install golang-go）" >&2
    exit 1
}

# 版本号取 git 描述，脱离 git 时退化成日期。启动日志和 --version 都会打印它，
# 部署脚本靠它判断"传上去的二进制到底是不是新的"。
VERSION="$(git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d)"
COMMIT_TIME="$(git log -1 --format=%cI 2>/dev/null || true)"

mkdir -p dist

for ARCH in "${ARCHS[@]}"; do
    OUT="dist/ipv6-proxy-linux-${ARCH}"
    echo "==> 编译 linux/${ARCH}  版本 ${VERSION}"

    # CGO_ENABLED=0 是关键：关掉 cgo 才是真正的静态链接，
    # 不依赖目标机的 glibc 版本。本项目只用到 golang.org/x/sys（纯 Go），
    # 关掉没有任何功能损失。
    #
    # 顺带把默认的 DNS 解析器钉成纯 Go 实现：cgo 关闭时本来就是这样，
    # 写出来是为了让"为什么不读 /etc/nsswitch.conf"这件事有据可查。
    #
    # -s -w 去掉符号表和 DWARF，二进制从 ~7MB 降到 ~4.5MB。
    # 这个服务出问题看日志，不做 core dump 分析，符号表用不上。
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -trimpath \
            -ldflags "-s -w -X main.version=${VERSION}" \
            -o "$OUT" .

    SIZE="$(du -h "$OUT" | cut -f1 | tr -d ' ')"
    echo "    $OUT  ($SIZE)"
done

if [ -n "$COMMIT_TIME" ]; then
    echo
    echo "源码提交时间: $COMMIT_TIME"
fi

echo
echo "下一步——把二进制和部署脚本一起传到服务器："
echo "  scp dist/ipv6-proxy-linux-amd64 deploy.sh root@服务器:/tmp/"
echo "  ssh root@服务器 'cd /tmp && ./deploy.sh --binary ./ipv6-proxy-linux-amd64'"
