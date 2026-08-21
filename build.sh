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

# 校验和跟二进制一起提交，方便核对下载到的文件有没有被改过或传坏。
( cd dist && if command -v sha256sum >/dev/null 2>&1; then
      sha256sum ipv6-proxy-linux-* > SHA256SUMS
  else
      shasum -a 256 ipv6-proxy-linux-* > SHA256SUMS
  fi )
echo "    dist/SHA256SUMS"

if [ -n "$COMMIT_TIME" ]; then
    echo
    echo "源码提交时间: $COMMIT_TIME"
fi

case "$VERSION" in
    *-dirty)
        echo
        echo "注意：版本号带 -dirty，说明工作区有未提交的改动。"
        echo "     提交之后重新跑一次 ./build.sh，版本号才对得上仓库里的 commit。"
        ;;
esac

echo
echo "下一步——提交二进制并推送："
echo "  git add -A && git commit -m '...' && git push"
echo
echo "服务器上安装（只需要 deploy.sh 一个文件，二进制会自动下载）："
echo "  curl -fsSL https://raw.githubusercontent.com/1198722360/ipv6-proxy/main/deploy.sh -o deploy.sh"
echo "  chmod +x deploy.sh && sudo ./deploy.sh"
