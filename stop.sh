#!/usr/bin/env bash
#
# 一键停止 ipv6-proxy。
#
# 用法：
#   sudo ./stop.sh              # 停止服务（保留开机自启，重启机器还会起来）
#   sudo ./stop.sh --disable    # 停止并关掉开机自启
#   sudo ./stop.sh --force      # 上面都没停掉时，直接 kill 进程
#   sudo ./stop.sh --status     # 只看状态，不做任何改动
#
# 想彻底卸载（删二进制、unit、用户）用 deploy.sh --uninstall。

set -euo pipefail

UNIT=ipv6-proxy.service
ROUTE_UNIT=ipv6-proxy-route.service

DISABLE=0
FORCE=0
STATUS_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --disable) DISABLE=1 ;;
        --force)   FORCE=1 ;;
        --status)  STATUS_ONLY=1 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "未知参数：$arg（--help 看用法）" >&2; exit 1 ;;
    esac
done

# stray_pids 列出**不归 systemd 管**的 ipv6-proxy 进程。
#
# 直接 pgrep 会把服务自己的进程也算进去，于是服务正常跑着的时候
# --status 会报"有野进程"，让人白追一场。用 systemd 记录的 MainPID
# 把它排除掉。
stray_pids() {
    main=""
    if command -v systemctl >/dev/null 2>&1; then
        main="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null || true)"
    fi
    pgrep -x ipv6-proxy 2>/dev/null | while read -r p; do
        [ "$p" = "$main" ] || echo "$p"
    done
}

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
log()  { printf '  %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

echo
echo "ipv6-proxy 停止"
echo "────────────────────────────────────────"

# ── 只看状态 ──
if [ "$STATUS_ONLY" = 1 ]; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        ok "服务运行中"
        if systemctl is-enabled "$UNIT" >/dev/null 2>&1; then
            log "开机自启：已启用"
        else
            log "开机自启：未启用"
        fi
    else
        log "服务未运行"
    fi
    # 漏网进程：手工用二进制起的那种。
    # 必须排除 systemd 自己管的那个 PID，否则服务正常运行时也会报
    # "有 systemd 之外的进程"，让人去追一个根本不存在的野进程。
    STRAY="$(stray_pids)"
    if [ -n "$STRAY" ]; then
        warn "有 systemd 之外的 ipv6-proxy 进程："
        echo "$STRAY" | while read -r p; do
            [ -n "$p" ] && log "    $p $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)"
        done
    fi
    if command -v ss >/dev/null 2>&1; then
        PORTS="$(ss -lntp 2>/dev/null | grep ipv6-proxy || true)"
        if [ -n "$PORTS" ]; then
            log "监听中的端口："
            echo "$PORTS" | awk '{print "      " $4}'
        fi
    fi
    echo
    exit 0
fi

[ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"

STOPPED=0

# ── systemd 托管的服务 ──
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        systemctl stop "$UNIT"
        ok "已停止 $UNIT"
        STOPPED=1
    else
        log "$UNIT 未在运行"
    fi

    if [ "$DISABLE" = 1 ]; then
        if systemctl is-enabled "$UNIT" >/dev/null 2>&1; then
            systemctl disable "$UNIT" >/dev/null 2>&1
            ok "已关闭开机自启"
        else
            log "开机自启本来就没开"
        fi
        # local 路由那个 unit 不动：它只是往 lo 上加一条路由，
        # 不占端口、不跑进程，留着不影响任何东西，而且下次启动还要用。
        log "保留 $ROUTE_UNIT（只是一条 lo 路由，不占资源）"
    fi
else
    warn "没有 systemctl，跳过服务停止"
fi

# ── 漏网进程 ──
# systemctl stop 只管它自己启动的那个。手工跑二进制起的进程（调试、
# 自检残留）它看不到，那些进程还占着 6080/6081，下次启动会 bind 失败。
sleep 0.5
STRAY="$(stray_pids)"
if [ -n "$STRAY" ]; then
    if [ "$FORCE" = 1 ]; then
        # 只杀野进程。无差别 pkill 会连 systemd 管的那个一起杀，
        # 而 unit 里是 Restart=always——它会立刻被拉起来，看上去像"杀不掉"。
        echo "$STRAY" | xargs -r kill 2>/dev/null || true
        sleep 1
        REMAIN="$(stray_pids)"
        if [ -n "$REMAIN" ]; then
            echo "$REMAIN" | xargs -r kill -9 2>/dev/null || true
            sleep 0.5
            ok "已强制杀掉残留进程（SIGKILL）"
        else
            ok "已终止残留进程（SIGTERM）"
        fi
        STOPPED=1
    else
        warn "还有 ipv6-proxy 进程在跑（不是 systemd 启的）："
        echo "$STRAY" | while read -r p; do
            [ -n "$p" ] && log "    $p $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)"
        done
        log "这些进程仍占着端口，下次启动会 bind 失败。"
        log "要一并停掉：sudo $0 --force"
    fi
fi

# ── 确认端口真的释放了 ──
# "服务已停止"不等于"端口空了"：残留进程、TIME_WAIT 里的监听套接字
# 都会让下一次启动失败，而那时的报错是 bind: address already in use，
# 看不出跟这次停止有关。
echo
if command -v ss >/dev/null 2>&1; then
    BUSY="$(ss -lntp 2>/dev/null | grep ipv6-proxy || true)"
    if [ -n "$BUSY" ]; then
        warn "仍有端口被占用："
        echo "$BUSY" | awk '{print "      " $4}'
        [ "$FORCE" = 1 ] || log "试试：sudo $0 --force"
    else
        ok "端口已全部释放"
    fi
else
    log "没有 ss，无法确认端口是否释放"
fi

echo
echo "────────────────────────────────────────"
if [ "$STOPPED" = 1 ]; then
    ok "已停止"
else
    log "没有正在运行的服务"
fi
echo
log "重新启动    sudo systemctl start $UNIT"
if [ "$DISABLE" = 1 ]; then
    log "恢复自启    sudo systemctl enable --now $UNIT"
fi
log "查看日志    journalctl -u $UNIT -n 50"
log "彻底卸载    sudo ./deploy.sh --uninstall"
echo
