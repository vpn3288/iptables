#!/bin/bash
# port.sh v4.6 — 代理节点防火墙管理脚本
# 支持: Hysteria2端口跳跃 | X-UI/3x-ui/Marzban | sing-box | xray | v2ray | WireGuard | Trojan | TUIC | Naive
# 兼容: Oracle Cloud ARM | 各大 VPS | Docker 环境 | IPv6 双栈
#
# ══════════════════ 修复清单（相对 v4.0/v4.1）════════════════════
# [A1] IPv6 DNAT 语法: --to-destination ":PORT" → "[::]:PORT"
#      ip6tables 不接受仅端口格式，必须用 [IPv6地址]:端口 形式
# [A2] install_deps: 补充 python3 依赖检测与自动安装
# [A3] install_deps: ip6tables 不是独立 apt 包（属于 iptables），
#      移除错误的 ip6tables 包名；改为检测并提示
# [A4] install_deps: sysctl net.ipv4.ip_forward 缺少 || true，
#      在 set -uo pipefail 下若 sysctl 失败会直接退出
# [A5] detect_ssh: sshd? 正则改为 sshd（? 多余且可能误匹配）
# [A6] detect_existing_hop_rules: 显示格式修正（range 本已含'-'）
# [A7] apply_hop: IPv6 旧 DNAT 规则未清理，导致规则重复叠加
# [A8] apply_hop: fallback 命令末尾缺 || true，两种格式均失败
#      时 set -uo pipefail 会退出整个脚本
# [A9] FORWARD --ctstate NEW 移除：DNAT 到本机时包走 INPUT
#      而非 FORWARD，NEW 规则使 VPS 变成开放路由器（安全漏洞）
# [A10] is_blacklisted: 移除面板管理端口黑名单（54321/2053/2087/2096）
#       运行中的面板由 ss 自然检测到并放行；未运行的不放行是正确的
#       一刀切拉黑会导致普通用户面板突然无法访问（UX 灾难）
# [A11] detect_ports: Marzban 端口提取后未调用 add_port（变量孤立）
# [A12] save_rules: systemd 服务创建后只 enable 未启动；
#       服务处于 dead/failed 状态时 try-restart 什么都不做（误解）
#       修复: 改用 restart，无论当前状态如何都强制拉起
# [A13] main: trap 补充 EXIT 清理临时 Python 文件
# [A14] install_deps: 若检测到 X-UI/3x-ui 数据库则自动安装 sqlite3
# [B1] Python 解析器: 新增 JSONC 注释剥离（状态机方式）
#      兼容 Xray/Hysteria2 广泛使用的 // 和 /* */ 注释
#      Gemini 建议的 re.sub 方案有误（会破坏 URL 中的 //），改为正确实现
# [B2] Marzban 端口提取: tr -d ' \r' → tr -d '[:space:]'
#      防止 "UVICORN_PORT = 8080"（等号两侧有空格/Tab）导致解析失败
# [B3] apply_hop grep: 增加 ([^0-9]|$) 端边界
#      防止 grep "dpts:100:200" 误匹配 "dpts:100:2000" 并删错规则
# [B4] detect_hysteria_hop 内联 Python: json.load → strip_jsonc + json.loads
#      与 detect_ports 保持一致，正确处理含注释的 Hysteria2 config.json
# ══════════════════ 修复清单（相对 v4.3）════════════════════
# [C1] apply_hop INPUT 规则架构 Bug（核心级）:
#      DNAT 在 PREROUTING 阶段将目标端口从 s:e 改为 t，filter INPUT
#      看到的是 post-DNAT 的端口 t，而非原始范围 s:e。
#      原来的 INPUT --dport s:e 规则是死代码，跳跃实际上靠 OPEN_PORTS
#      里恰好有 443/80 才能工作；自定义目标端口时会静默失败。
#      修复: INPUT ACCEPT 改为目标端口 t，并确保目标端口加入 OPEN_PORTS。
# [C2] detect_hysteria_hop: 检测到跳跃规则时只写 HOP_RULES，未调用
#      add_port 将目标端口加入 OPEN_PORTS；若服务未运行（ss 扫不到），
#      目标端口就缺失 INPUT ACCEPT，导致 DNAT 后的包被 DROP 丢弃。
# [C3] add_hop_interactive: 直接调用 apply_hop → 规则追加在 DROP 之后
#      （iptables 从上往下匹配，DROP 先命中，跳跃永远不通）。
#      修复: 重新走完整主流程（detect + apply_rules）重建防火墙。
# [C4] reset_fw: iptables -t nat -F 暴力清空 NAT 表会断掉所有 Docker
#      容器的端口映射；flush 之后必须重启 Docker 重建网络链。
# [C5] _PY_PARSER: mktemp 无 fallback，/tmp 满或权限问题时脚本 abort。
# [C6] cfg_files 数组重复: config.json 同时匹配 "config.json" 和 "*.json"
#      两个 glob，同一文件被 Python 重复解析（功能无害但浪费资源）。
# [C7] IPv6 DROP 前缺少 LOG 规则，与 IPv4 行为不一致，难以排查拦截。
# [C8] is_blacklisted 注释错误: 323 是 RPKI-RTR 端口，非 NTP(123)。
# [C9] apply_rules: 未预加载 nf_conntrack/xt_recent 内核模块；在
#      最小化 VPS / LXC 容器环境下，-m conntrack/-m recent 会静默失败
#      导致整个防火墙规则集无效。
# [C10] detect_existing_hop_rules: 只读 IPv4 iptables；若仅剩 IPv6 规则
#       存活（重启后 IPv4 规则未持久化等边缘场景），已有跳跃配置会丢失。
# ═════════════════════════════════════════════════════════════

set -uo pipefail

# ── 颜色 & 工具函数 ──────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠  $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

SSH_PORT="" OPEN_PORTS=() HOP_RULES=() VERSION="4.6" DRY_RUN=false
_status=0 _reset=0 _addhop=0
_DOCKER_RUNNING=0    # flush_rules 检测 Docker，apply_rules 结束后重启
_PY_PARSER=""        # Python 临时文件路径，EXIT trap 清理

for arg in "$@"; do case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --status)  _status=1 ;;
    --reset)   _reset=1 ;;
    --add-hop) _addhop=1 ;;
    --help|-h)
        echo "用法: bash port.sh [选项]"
        echo "  （无参数）    自动检测并配置防火墙"
        echo "  --dry-run     预览模式，不实际修改规则"
        echo "  --status      显示当前防火墙状态"
        echo "  --reset       清除所有规则（全部放行）"
        echo "  --add-hop     手动添加 Hysteria2 端口跳跃规则"
        echo "  --help        显示帮助"
        exit 0 ;;
    *) err "未知参数: $arg（用 --help 查看用法）" ;;
esac; done

# [A5 前置] systemd-resolve 与 systemd\.resolve 同时兼容（进程名含点）
EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|systemd\.resolve|named|unbound|ntpd|avahi|NetworkManager"

# ============================================================
# _cleanup: EXIT trap，清理临时文件
# [A13 FIX] 脚本退出时自动清理 Python 解析器临时文件
# ============================================================
_cleanup() {
    [[ -n "${_PY_PARSER:-}" && -f "$_PY_PARSER" ]] && rm -f "$_PY_PARSER" 2>/dev/null || true
}
trap '_cleanup' EXIT
trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM

# ============================================================
# get_public_ports: ss 扫描公网监听端口（全端口范围，不截断高位）
# ============================================================
get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | sort -un || true
}

# ============================================================
# install_deps: 安装依赖、配置 sysctl、停用防火墙前端
# ============================================================
install_deps() {
    # [C9 FIX] 预加载 iptables 依赖内核模块
    # 在最小化 VPS / LXC 容器环境中，-m conntrack/-m recent 会因模块未加载
    # 而静默失败，导致整个防火墙规则集（含 SSH 防爆破）完全失效
    for mod in nf_conntrack nf_conntrack_ipv4 nf_conntrack_ipv6 \
               xt_conntrack xt_recent xt_LOG xt_limit; do
        modprobe "$mod" 2>/dev/null || true
    done

    local pkgs=()

    # 基础工具
    command -v iptables &>/dev/null || pkgs+=(iptables)
    command -v ss       &>/dev/null || pkgs+=(iproute2)

    # [A2 FIX] python3 依赖：若缺失则静默失败会导致配置文件解析全盘跳过
    command -v python3  &>/dev/null || pkgs+=(python3)

    # [A3 FIX] ip6tables 在 Debian/Ubuntu 随 iptables 包一起安装，无独立包名
    # RHEL/CentOS 7 可能需要 iptables-ipv6 独立包；RHEL 8+ 已内置
    if ! command -v ip6tables &>/dev/null; then
        if command -v yum &>/dev/null || command -v dnf &>/dev/null; then
            pkgs+=(iptables-ipv6)  # CentOS/RHEL 7 独立包名
        fi
        # Debian/Ubuntu: ip6tables 随 iptables 包安装，已在前面加入 pkgs
    fi

    # [A14 FIX] 若存在 X-UI/3x-ui 数据库则安装 sqlite3
    local _need_sqlite=0
    for db in /etc/x-ui/x-ui.db /usr/local/x-ui/bin/x-ui.db \
              /opt/3x-ui/bin/x-ui.db /usr/local/x-ui/x-ui.db; do
        [[ -f "$db" ]] && _need_sqlite=1 && break
    done
    if [[ $_need_sqlite -eq 1 ]] && ! command -v sqlite3 &>/dev/null; then
        pkgs+=(sqlite3)
    fi

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null || true
            apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y -q "${pkgs[@]}" 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y -q "${pkgs[@]}" 2>/dev/null || true
        fi
    fi

    # [BUG12] 禁用 firewalld / ufw，防止与 iptables 规则打架
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        warn "检测到 firewalld 正在运行，停止并禁用以避免规则冲突..."
        systemctl disable --now firewalld 2>/dev/null || true
        ok "firewalld 已禁用"
    fi
    if systemctl is-active --quiet ufw 2>/dev/null; then
        warn "检测到 ufw 正在运行，停止并禁用以避免规则冲突..."
        ufw --force disable 2>/dev/null || true
        systemctl disable --now ufw 2>/dev/null || true
        ok "ufw 已禁用"
    fi

    # ── IPv4 转发（端口跳跃 NAT 必须）──────────────────────────
    # [A4 FIX] 补充 || true，sysctl 失败时（如某些容器环境）不退出脚本
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null || true

    # ── IPv6 转发（甲骨文 ARM 双栈、IPv6 跳跃必须）────────────
    sysctl -w net.ipv6.conf.all.forwarding=1     &>/dev/null || true
    sysctl -w net.ipv6.conf.default.forwarding=1 &>/dev/null || true

    # ── 安全加固 ──────────────────────────────────────────────
    sysctl -w net.ipv4.conf.all.send_redirects=0      &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0    &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true

    # tcp_timestamps=0：防信息泄露，与 youhua.sh v2.4 一致
    sysctl -w net.ipv4.tcp_timestamps=0 &>/dev/null || true

    # rp_filter=2 宽松模式：=1 严格模式会丢弃端口跳跃的 UDP 转发包
    sysctl -w net.ipv4.conf.all.rp_filter=2     &>/dev/null || true
    sysctl -w net.ipv4.conf.default.rp_filter=2 &>/dev/null || true

    # 持久化到独立文件，不污染其他脚本写入的 sysctl.conf
    cat > /etc/sysctl.d/98-port-firewall.conf << 'EOF'
# port.sh v4.4 — 与 youhua.sh v2.4 / BBRplus 完全兼容
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_timestamps=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-port-firewall.conf &>/dev/null || true
    # --system 重载所有 /etc/sysctl.d/*.conf，确保与其他脚本写入的参数不冲突
    sysctl --system &>/dev/null || true
    ok "sysctl 参数已写入 /etc/sysctl.d/98-port-firewall.conf"
}

# ============================================================
# detect_ssh: 检测 SSH 端口
# [A5 FIX] sshd? → sshd（? 多余，且 sshd? 可能匹配 "ssh" 子串）
# ============================================================
detect_ssh() {
    # 优先从 ss 实时监听状态获取（sshd 进程名）
    SSH_PORT=$(ss -tlnp 2>/dev/null \
        | grep -E '\bsshd\b' \
        | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
    # 备选：读取 sshd 配置（跳过注释行）
    [[ -z "$SSH_PORT" ]] && \
        SSH_PORT=$(grep -E '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1)
    # 最终默认值
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ============================================================
# parse_hop: 解析跳跃规则字符串 "20000-50000->443"
# 使用 bash 参数展开，无子进程，比 cut+tr 管道更可靠
# ============================================================
parse_hop() {
    local rule=$1
    HOP_S="${rule%%-*}"         # "20000-50000->443" → "20000"
    local _rest="${rule#*-}"    # → "50000->443"
    HOP_E="${_rest%%->*}"       # → "50000"
    HOP_T="${rule##*>}"         # → "443"
}

# ============================================================
# port_in_hop_range: 检查端口是否落在跳跃范围内（空数组安全）
# ============================================================
port_in_hop_range() {
    local p=$1
    [[ ${#HOP_RULES[@]} -eq 0 ]] && return 1
    local rule
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ -n "${HOP_S:-}" && -n "${HOP_E:-}" ]] || continue
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

# ============================================================
# is_blacklisted: 危险/系统端口黑名单（不对外暴露）
# [A10 FIX] 移除面板管理端口（54321/2053/2087/2096）
#   理由: 这些端口若正在运行，ss 会检测到并自然放行；
#         若未运行，不放行是正确的；一刀切拉黑会导致
#         用户运行脚本后面板突然无法访问（UX 灾难）
#   取而代之: show_summary 中给出安全使用建议
# ============================================================
is_blacklisted() {
    local p=$1
    # SSH 端口由专用规则（含防暴力破解）处理，不进入普通开放列表
    [[ "$p" == "$SSH_PORT" ]] && return 0
    case "$p" in
        # 危险/系统协议端口
        23|25|53|69|111|135|137|138|139|445|514|631) return 0 ;;
        # 邮件协议（不应在代理节点暴露）
        110|143|465|587|993|995) return 0 ;;
        # 数据库（严禁对外暴露）
        1433|1521|3306|5432|6379|27017) return 0 ;;
        # 远程桌面 / NFS / RPKI-RTR（323 是 RPKI-RTR，NTP 是 123）
        3389|5900|5901|5902|323|2049) return 0 ;;
        # 233boy xray 纯内部端口段（不对外暴露）
        10080|10081|10082|10083|10084|10085|10086) return 0 ;;
    esac
    return 1
}

# ============================================================
# add_port: 将端口加入开放列表（带校验和去重，空数组安全）
# ============================================================
add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]              || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                  && return 0
    port_in_hop_range "$p"              && return 0
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        # 用 glob 通配符而非 =~（正则），对端口数字更安全且语义更明确
        [[ " ${OPEN_PORTS[*]} " == *" $p "* ]] && return 0
    fi
    OPEN_PORTS+=("$p")
}

# ============================================================
# detect_existing_hop_rules: 从当前 iptables NAT 读取已有跳跃规则
# [A6 FIX] 显示时直接使用 range（已含'-'），不再做 ${range/-/:} 转换
# 兼容 iptables 显示: to::PORT / to:0.0.0.0:PORT / to:[::]:PORT
# [C10 FIX] 同时读取 IPv6 iptables，防止仅剩 IPv6 规则时跳跃配置丢失
# ============================================================
detect_existing_hop_rules() {
    _parse_nat_for_hops() {
        # 从一段 iptables/ip6tables PREROUTING 输出中提取跳跃规则
        while IFS= read -r line; do
            [[ "$line" == *DNAT* ]] || continue
            local range target
            range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' \
                | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
            target=$(echo "$line" \
                | grep -oE 'to:(\[::]\:|:)[0-9]+|to:[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+' \
                | grep -oE '[0-9]+$')
            [[ -n "$range" && -n "$target" ]] || continue
            local rule="${range}->${target}"
            if [[ ${#HOP_RULES[@]} -eq 0 ]] || \
               [[ ! " ${HOP_RULES[*]} " =~ " ${rule} " ]]; then
                HOP_RULES+=("$rule")
                info "读取已有跳跃规则: ${range} → ${target}"
            fi
        done
    }

    # IPv4
    _parse_nat_for_hops < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)

    # [C10 FIX] IPv6
    if command -v ip6tables &>/dev/null; then
        _parse_nat_for_hops < <(ip6tables -t nat -L PREROUTING -n 2>/dev/null || true)
    fi
}

# ============================================================
# detect_hysteria_hop: 从 Hysteria2 配置文件检测端口跳跃
# YAML: awk 兼容 "listen: :443" 和 "listen: 443" 两种格式
# JSON: 内嵌 Python 精确解析，兼容 listen_port 字段
# 无跳跃但有 listen 端口时，自动 add_port
# ============================================================
detect_hysteria_hop() {
    local dirs=(
        /etc/hysteria  /etc/hysteria2
        /usr/local/etc/hysteria  /usr/local/etc/hysteria2
    )
    local file_names=(config server)

    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for fname in "${file_names[@]}"; do
            for ext in json yaml yml; do
                local f="${d}/${fname}.${ext}"
                [[ -f "$f" ]] || continue
                local listen_port="" hop_range=""

                if [[ "$ext" == "json" ]]; then
                    # 兼容: "listen":":443" / "listen":"0.0.0.0:443" / "listen_port":443
                    # [B4 FIX] 使用状态机剥离 JSONC 注释，与 detect_ports 解析器保持一致
                    if command -v python3 &>/dev/null; then
                        listen_port=$(python3 - "$f" 2>/dev/null << 'PYEOF'
import json, sys, re

def strip_jsonc(s):
    """状态机剥离 // 和 /* */ 注释，正确跳过字符串内容（如 URL 中的 //）"""
    out=[]; i=0; n=len(s); in_str=False
    while i<n:
        c=s[i]
        if in_str:
            if c=='\\' and i+1<n: out.append(c); out.append(s[i+1]); i+=2; continue
            elif c=='"': in_str=False
            out.append(c)
        else:
            if c=='"': in_str=True; out.append(c)
            elif s[i:i+2]=='//':
                while i<n and s[i]!='\n': i+=1; continue
            elif s[i:i+2]=='/*':
                end=s.find('*/',i+2); i=(end+2) if end!=-1 else n; continue
            else: out.append(c)
        i+=1
    return ''.join(out)

try:
    with open(sys.argv[1], encoding='utf-8', errors='ignore') as fp:
        raw = fp.read()
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        d = json.loads(strip_jsonc(raw))
    v = str(d.get('listen',''))
    if v:
        m = re.search(r':(\d+)$', v)
        if m: print(m.group(1)); raise SystemExit
    lp = d.get('listen_port')
    if isinstance(lp, int) and 1 <= lp <= 65535:
        print(lp)
except SystemExit: pass
except Exception: pass
PYEOF
                        )
                    fi
                    hop_range=$(grep -oE \
                        '"(portHopping|portRange|hop)"\s*:\s*"[0-9]+-[0-9]+"' \
                        "$f" 2>/dev/null \
                        | grep -oE '[0-9]+-[0-9]+' | head -1)
                else
                    # YAML: awk 逐字段提取，兼容 ":PORT" 和纯数字 "PORT" 两种写法
                    listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                        | awk -F: '{
                            for(i=NF;i>=1;i--) {
                                gsub(/[^0-9]/,"",$i)
                                if($i~/^[0-9]+$/ && $i+0>=1 && $i+0<=65535) {
                                    print $i; exit
                                }
                            }
                          }' | head -1)
                    hop_range=$(grep -E \
                        '^\s*(portHopping|portRange|hop)\s*:' \
                        "$f" 2>/dev/null \
                        | grep -oE '[0-9]+-[0-9]+' | head -1)
                fi

                if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                    local rule="${hop_range}->${listen_port}"
                    local already=0
                    [[ ${#HOP_RULES[@]} -gt 0 ]] && \
                        [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] && already=1
                    if [[ $already -eq 0 ]]; then
                        HOP_RULES+=("$rule")
                        ok "检测到 Hysteria2 端口跳跃 ($f): $hop_range → $listen_port"
                    fi
                    # [C2 FIX] 有跳跃时同样必须确保目标端口加入 OPEN_PORTS：
                    # DNAT 在 PREROUTING 把外部端口改为 listen_port 后，
                    # filter INPUT 看到的是 post-DNAT 的目标端口 listen_port，
                    # 若 OPEN_PORTS 里没有它，数据包会被末尾的 DROP 丢弃。
                    add_port "$listen_port"
                elif [[ -n "$listen_port" ]]; then
                    # 有监听端口但无跳跃配置时，确保固定端口被放行
                    add_port "$listen_port"
                    info "Hysteria2 固定监听端口 ($f): $listen_port"
                fi
            done
        done
    done
}

# ============================================================
# detect_ports: 综合端口扫描（ss + 配置文件 + 数据库）
# ============================================================
detect_ports() {
    info "扫描公网监听端口..."

    # ── 1. ss 实时扫描（最可靠）──────────────────────────────
    while read -r port; do
        add_port "$port"
    done < <(get_public_ports)

    # ── 2. WireGuard 端口检测 ─────────────────────────────────
    if command -v wg &>/dev/null; then
        while IFS= read -r line; do
            local wg_port
            wg_port=$(echo "$line" | awk '{print $NF}')
            [[ "$wg_port" =~ ^[0-9]+$ ]] && add_port "$wg_port"
        done < <(wg show all listen-port 2>/dev/null || true)
    fi
    # WireGuard 配置文件兜底（wg 进程未运行时）
    for wg_conf in /etc/wireguard/*.conf /usr/local/etc/wireguard/*.conf; do
        [[ -f "$wg_conf" ]] || continue
        local wg_port
        wg_port=$(grep -iE '^[[:space:]]*ListenPort[[:space:]]*=' "$wg_conf" \
            | grep -oE '[0-9]+' | head -1)
        [[ -n "$wg_port" ]] && add_port "$wg_port" && \
            info "WireGuard 配置端口 ($wg_conf): $wg_port"
    done

    # ── 3. 配置文件补充（覆盖未运行节点的端口）──────────────
    # 构建 Python 解析器（带 YAML 支持）
    # [C5 FIX] mktemp 加 fallback：/tmp 权限受限或磁盘满时不 abort
    # [v4.5 FIX] 增强 fallback 逻辑，支持用户目录
    _PY_PARSER=$(mktemp /tmp/_fw_parse_ports_XXXXXX.py 2>/dev/null)
    if [[ -z "$_PY_PARSER" || ! -w "$(dirname "$_PY_PARSER" 2>/dev/null || echo /tmp)" ]]; then
        # 尝试用户目录
        local cache_dir="${HOME}/.cache"
        mkdir -p "$cache_dir" 2>/dev/null || cache_dir="/tmp"
        _PY_PARSER="${cache_dir}/_fw_parse_ports_$$.py"
        if ! touch "$_PY_PARSER" 2>/dev/null; then
            warn "无法创建临时文件，跳过配置文件解析"
            _PY_PARSER=""
        fi
    fi
    
    if [[ -z "$_PY_PARSER" ]]; then
        warn "Python解析器初始化失败，仅依赖 ss 实时扫描结果"
    else
        cat > "$_PY_PARSER" << 'PYEOF'
import json, sys, re, os

# 尝试导入 PyYAML（可选依赖，无则跳过 YAML 文件）
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def parse_addr_port(v):
    """
    从各种地址格式提取端口数字:
      ':443' / '0.0.0.0:443' / '[::]:443' / '443' / 443
    """
    if v is None: return None
    if isinstance(v, int): return v if 1 <= v <= 65535 else None
    s = str(v).strip()
    # 纯数字字符串
    if s.isdigit():
        p = int(s); return p if 1 <= p <= 65535 else None
    # 末尾 :数字（兼容 IPv4/IPv6/仅端口 三种格式）
    m = re.search(r':(\d+)$', s)
    if m:
        p = int(m.group(1)); return p if 1 <= p <= 65535 else None
    return None

def is_local_bind(v):
    """127.x / ::1 / localhost 视为本地绑定，不放行"""
    s = str(v or '').strip()
    return s.startswith('127.') or s in ('::1', 'localhost', '::1')

def extract_json(data):
    if not isinstance(data, dict): return []
    ports = []

    # V2Ray / Xray / sing-box: inbounds[].port / listen_port
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        if is_local_bind(inb.get('listen', '')): continue
        for key in ('port', 'listen_port'):
            p = parse_addr_port(inb.get(key))
            if p: ports.append(p)

    # V2Ray 旧格式: inbound / inboundDetour
    for src in ([data.get('inbound')] + list(data.get('inboundDetour') or [])):
        if not isinstance(src, dict): continue
        if is_local_bind(src.get('listen', '')): continue
        p = parse_addr_port(src.get('port'))
        if p: ports.append(p)

    # Trojan / Trojan-Go: local_port
    p = parse_addr_port(data.get('local_port'))
    if p: ports.append(p)

    # Hysteria2 / TUIC / Naive: listen / listen_addr
    for key in ('listen', 'listen_addr'):
        v = data.get(key)
        if v and not is_local_bind(v):
            p = parse_addr_port(v)
            if p: ports.append(p)

    # TUIC v5: server: "0.0.0.0:443"
    server = data.get('server', '')
    if isinstance(server, str) and not is_local_bind(server):
        p = parse_addr_port(server)
        if p: ports.append(p)

    return sorted(set(ports))

def extract_yaml(data):
    """YAML 格式 (Hysteria2 / sing-box YAML)"""
    if not isinstance(data, dict): return []
    ports = []

    for key in ('listen', 'server', 'listen_addr'):
        v = data.get(key)
        if v and not is_local_bind(str(v)):
            p = parse_addr_port(v)
            if p: ports.append(p)

    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('listen_port', 'port'):
            p = parse_addr_port(inb.get(key))
            if p: ports.append(p)

    return sorted(set(ports))

def strip_jsonc_comments(s):
    """
    剥离 JSON 中的非标准注释（Xray/Hysteria2 等广泛使用）:
      // 单行注释  和  /* */ 块注释
    使用状态机逐字符解析，正确跳过字符串内容（如 URL 中的 //）。
    """
    out = []
    i = 0
    n = len(s)
    in_str = False
    while i < n:
        c = s[i]
        if in_str:
            # 字符串内：处理转义序列，保留所有字符
            if c == '\\' and i + 1 < n:
                out.append(c)
                out.append(s[i + 1])
                i += 2
                continue
            elif c == '"':
                in_str = False
            out.append(c)
        else:
            if c == '"':
                in_str = True
                out.append(c)
            elif s[i:i+2] == '//':
                # 单行注释：跳过到行尾（保留换行符以维持行号）
                while i < n and s[i] != '\n':
                    i += 1
                continue
            elif s[i:i+2] == '/*':
                # 块注释：跳过到 */
                end = s.find('*/', i + 2)
                i = (end + 2) if end != -1 else n
                continue
            else:
                out.append(c)
        i += 1
    return ''.join(out)

for f in sys.argv[1:]:
    try:
        ext = os.path.splitext(f)[1].lower()
        with open(f, encoding='utf-8', errors='ignore') as fp:
            content = fp.read()
        if ext in ('.yaml', '.yml') and HAS_YAML:
            data = yaml.safe_load(content)
            for p in extract_yaml(data): print(p)
        else:
            # 先尝试标准 JSON，失败时再剥离注释后重试（兼容 Xray JSONC 格式）
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                data = json.loads(strip_jsonc_comments(content))
            for p in extract_json(data): print(p)
    except Exception:
        pass
PYEOF
    fi

    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray    /etc/xray
        /usr/local/etc/v2ray   /etc/v2ray
        /etc/sing-box          /opt/sing-box     /usr/local/etc/sing-box
        /etc/hysteria          /etc/hysteria2
        /usr/local/etc/hysteria /usr/local/etc/hysteria2
        /etc/tuic              /usr/local/etc/tuic
        /etc/trojan            /etc/trojan-go
        /usr/local/etc/trojan  /usr/local/etc/trojan-go
        /etc/naiveproxy        /usr/local/etc/naive    /usr/local/etc/naiveproxy
        /etc/brook             /usr/local/etc/brook
        /etc/x-ui              /usr/local/x-ui/bin
        /opt/3x-ui             /opt/3x-ui/bin
        /opt/marzban
        /etc/amnezia           /etc/amneziawg
        /etc/gost              /usr/local/etc/gost
    )

    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for pat in "config.json" "config.yaml" "config.yml" \
                   "server.json" "server.yaml" "server.yml" \
                   "*.json" "conf/*.json" "confs/*.json"; do
            for f in "${d}"/${pat}; do
                [[ -f "$f" ]] && cfg_files+=("$f")
            done
        done
    done
    # Marzban Xray 核心配置（单独路径）
    for mz_cfg in /opt/marzban/xray_config.json /var/lib/marzban/xray_config.json; do
        [[ -f "$mz_cfg" ]] && cfg_files+=("$mz_cfg")
    done

    if [[ ${#cfg_files[@]} -gt 0 ]] && [[ -n "$_PY_PARSER" ]] && command -v python3 &>/dev/null; then
        # [C6 FIX] 去重：config.json 会同时命中 "config.json" 和 "*.json" 两个 glob，
        # 导致同一文件被 Python 重复解析。用关联数组去重后再传给解析器。
        declare -A _seen_cfg=()
        local _unique_cfgs=()
        for _f in "${cfg_files[@]}"; do
            [[ -z "${_seen_cfg[$_f]+x}" ]] && _unique_cfgs+=("$_f") && _seen_cfg[$_f]=1
        done
        unset _seen_cfg
        while read -r port; do
            add_port "$port"
        done < <(python3 "$_PY_PARSER" "${_unique_cfgs[@]}" 2>/dev/null | sort -un || true)
    elif [[ ${#cfg_files[@]} -gt 0 ]]; then
        warn "python3 未安装或解析器初始化失败，跳过配置文件解析；仅依赖 ss 实时扫描结果"
    fi

    # ── 4. X-UI / 3x-ui SQLite 数据库读取 ───────────────────
    for db in /etc/x-ui/x-ui.db \
              /usr/local/x-ui/bin/x-ui.db \
              /opt/3x-ui/bin/x-ui.db \
              /usr/local/x-ui/x-ui.db; do
        [[ -f "$db" ]] || continue
        if command -v sqlite3 &>/dev/null; then
            while read -r xui_port; do
                [[ "$xui_port" =~ ^[0-9]+$ ]] && add_port "$xui_port"
            done < <(sqlite3 "$db" \
                "SELECT port FROM inbounds WHERE enable=1;" 2>/dev/null || true)
            ok "已从 X-UI 数据库读取启用节点端口: $db"
        else
            warn "检测到 X-UI 数据库: $db（sqlite3 缺失，跳过读取）"
            warn "★ 请确保所有 X-UI/3x-ui 节点处于【运行中】状态后再执行本脚本！"
        fi
    done

    # ── 5. Marzban 面板端口 ───────────────────────────────────
    # [A11 FIX] 提取后必须调用 add_port，否则端口只打印不放行
    if [[ -f /opt/marzban/.env || -f /etc/opt/marzban/.env ]]; then
        local mz_env="/opt/marzban/.env"
        [[ -f "$mz_env" ]] || mz_env="/etc/opt/marzban/.env"
        local mz_port
        mz_port=$(grep -E '^UVICORN_PORT\s*=' "$mz_env" 2>/dev/null \
            | cut -d= -f2 | tr -d '[:space:]')
        if [[ -n "$mz_port" ]]; then
            add_port "$mz_port"
            info "Marzban 面板端口: $mz_port（已添加到放行列表）"
        fi
        warn "★ Marzban 节点端口存储在数据库，请确保所有节点处于【运行中】状态！"
    fi

    # ── 6. 233boy xray 文件名端口兜底 ────────────────────────
    # 命名约定: 端口号作为文件名前缀（如 443.json、10086.json）
    local conf_dirs=(
        /etc/xray/conf /etc/xray/confs
        /usr/local/etc/xray/conf /usr/local/etc/xray/confs
    )
    for d in "${conf_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local fname_port
            fname_port=$(basename "$f" .json | grep -oE '^[0-9]+$' || true)
            [[ -z "$fname_port" ]] && \
                fname_port=$(basename "$f" | grep -oE '^[0-9]+' || true)
            [[ -n "$fname_port" ]] && add_port "$fname_port"
        done
    done
}

# ============================================================
# apply_hop: 应用单条端口跳跃规则（IPv4 + IPv6）
# [A1 FIX]  IPv6 DNAT: ":PORT" → "[::]:PORT"（ip6tables 语法要求）
# [A7 FIX]  清理旧规则时同步清理 IPv6 的重复 DNAT 规则
# [A8 FIX]  fallback 命令末尾加 || true，防止两种格式均失败时退出
# ============================================================
apply_hop() {
    local s=$1 e=$2 t=$3

    # ── IPv4 清理旧规则 ────────────────────────────────────────
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep -E "dpts:${s}:${e}([^0-9]|$)" | awk '{print $1}' | sort -rn)
    for n in $nums; do iptables -t nat -D PREROUTING "$n" 2>/dev/null || true; done

    # ── IPv4 DNAT（":PORT" 形式；部分旧版 iptables 需 "0.0.0.0:PORT"）─
    # [A8 FIX] 两条命令用 || 连接，确保至少一条成功，末尾加 || true
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}" 2>/dev/null \
        || iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
           -j DNAT --to-destination "0.0.0.0:${t}" 2>/dev/null || true

    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}" 2>/dev/null \
        || iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
           -j DNAT --to-destination "0.0.0.0:${t}" 2>/dev/null || true

    # ── INPUT 链放行目标端口 ───────────────────────────────────
    # [C1 FIX] DNAT 在 PREROUTING 将目标端口从 s:e 改为 t，
    # filter INPUT 走的是 post-DNAT 路径，看到的目标端口是 t，
    # 原来的 --dport s:e 规则是死代码（永远不会被命中）。
    # 必须放行目标端口 t，才能让 DNAT 后的数据包通过 INPUT。
    iptables -C INPUT -p udp --dport "$t" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "$t" -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p tcp --dport "$t" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "$t" -j ACCEPT 2>/dev/null || true

    # ── IPv6 端口跳跃 ─────────────────────────────────────────
    if command -v ip6tables &>/dev/null; then
        # [A7 FIX] 先清理 IPv6 的旧规则，防止重复叠加
        local nums6
        nums6=$(ip6tables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
            | grep -E "dpts:${s}:${e}([^0-9]|$)" | awk '{print $1}' | sort -rn)
        for n in $nums6; do
            ip6tables -t nat -D PREROUTING "$n" 2>/dev/null || true
        done

        # [v4.5 FIX] IPv6 DNAT 目标地址优化：
        # 优先使用本机全局IPv6地址，回退到本地回环[::1]
        # [v4.6 FIX] 支持大写字母，增加地址格式验证
        local ipv6_target="[::1]"
        local ipv6_addr
        ipv6_addr=$(ip -6 addr show scope global 2>/dev/null \
            | grep -oP '(?<=inet6\s)[\da-fA-F:]+' | head -1)
        # 验证IPv6地址格式
        if [[ -n "$ipv6_addr" ]] && [[ "$ipv6_addr" =~ ^[0-9a-fA-F:]+$ ]]; then
            ipv6_target="[${ipv6_addr}]"
        fi
        
        ip6tables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
            -j DNAT --to-destination "${ipv6_target}:${t}" 2>/dev/null || true
        ip6tables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
            -j DNAT --to-destination "${ipv6_target}:${t}" 2>/dev/null || true

        # [C1 FIX] IPv6 INPUT 同样改为放行目标端口 t
        ip6tables -C INPUT -p udp --dport "$t" -j ACCEPT 2>/dev/null \
            || ip6tables -A INPUT -p udp --dport "$t" -j ACCEPT 2>/dev/null || true
        ip6tables -C INPUT -p tcp --dport "$t" -j ACCEPT 2>/dev/null \
            || ip6tables -A INPUT -p tcp --dport "$t" -j ACCEPT 2>/dev/null || true
    fi
}

# ============================================================
# flush_rules: 清空所有 iptables 规则（IPv4 + IPv6）
# 检测 Docker 运行状态，供 apply_rules 结束后重启
# ============================================================
flush_rules() {
    info "清理旧规则..."

    # 检测 Docker 是否运行（先于 flush，因为 flush 后 docker info 可能超时）
    _DOCKER_RUNNING=0
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        _DOCKER_RUNNING=1
        warn "检测到 Docker 正在运行，规则应用完成后将自动重启 Docker 以重建网络..."
    fi

    # IPv4
    iptables -P INPUT   ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables -F         2>/dev/null || true
    iptables -X         2>/dev/null || true
    iptables -t nat    -F 2>/dev/null || true
    iptables -t nat    -X 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true

    # IPv6
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   ACCEPT 2>/dev/null || true
        ip6tables -P FORWARD ACCEPT 2>/dev/null || true
        ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
        ip6tables -F         2>/dev/null || true
        ip6tables -X         2>/dev/null || true
        ip6tables -t nat    -F 2>/dev/null || true
        ip6tables -t nat    -X 2>/dev/null || true
        ip6tables -t mangle -F 2>/dev/null || true
    fi
}

# ============================================================
# apply_rules: 应用完整防火墙规则集（IPv4 + IPv6）
# [A9 FIX] FORWARD 移除 --ctstate NEW：
#   • DNAT 到本机时包走 INPUT，FORWARD 的 NEW 规则完全多余
#   • FORWARD NEW 会把 VPS 变成开放路由器（安全漏洞）
#   • 只保留 ESTABLISHED,RELATED 供 NAT 回程包使用
# ============================================================
apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        info "[预览] 开放端口: ${OPEN_PORTS[*]:-（无）}"
        [[ ${#HOP_RULES[@]} -gt 0 ]] && for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "[预览] 端口跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        return 0
    fi

    flush_rules

    # ═══════════════════════════════════════════════════════
    #  IPv4 规则
    # ═══════════════════════════════════════════════════════
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP ping 限速放行（防 ICMP 洪泛攻击）
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # ── SSH 防暴力破解（60 秒内超过 10 次连接则封锁）──────
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH_BF --update --seconds 60 --hitcount 10 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # ── 开放代理端口 ────────────────────────────────────────
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        for port in "${OPEN_PORTS[@]}"; do
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done
    fi

    # ── FORWARD 链 ─────────────────────────────────────────
    # [A9 FIX] 只放行 ESTABLISHED,RELATED（NAT 回程包）
    # 移除 --ctstate NEW：本机端口跳跃不经过 FORWARD 链，
    # 保留 NEW 会把 VPS 变成开放路由器
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ── 端口跳跃（Hysteria2 H2 协议必须）──────────────────
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            [[ -n "${HOP_S:-}" && -n "${HOP_E:-}" && -n "${HOP_T:-}" ]] || continue
            apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
            ok "端口跳跃已应用: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    fi

    # 限速日志（便于排查被拦截的连接，线上压力大时可注释）
    iptables -A INPUT -m limit --limit 5/min \
        -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP

    # ═══════════════════════════════════════════════════════
    #  IPv6 规则（甲骨文云 ARM / 现代 VPS 强依赖）
    #  ICMPv6 NDP 必须放行，否则 IPv6 地址解析失败、网络完全不通
    # ═══════════════════════════════════════════════════════
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   DROP   2>/dev/null || true
        ip6tables -P FORWARD DROP   2>/dev/null || true
        ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true

        ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED \
            -j ACCEPT 2>/dev/null || true

        # ICMPv6 NDP（邻居发现协议）—— 严禁全 DROP，缺少任意一条会断网
        for icmpv6_type in \
            neighbor-solicitation  \
            neighbor-advertisement \
            router-solicitation    \
            router-advertisement   \
            redirect; do
            ip6tables -A INPUT -p icmpv6 --icmpv6-type "$icmpv6_type" \
                -j ACCEPT 2>/dev/null || true
        done
        # ICMPv6 ping 限速
        ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request \
            -m limit --limit 5/sec --limit-burst 10 -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -p icmpv6 -j DROP 2>/dev/null || true

        # SSH（IPv6）防暴力破解
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" \
            -m recent --name SSH6_BF --set 2>/dev/null || true
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" \
            -m recent --name SSH6_BF --update --seconds 60 --hitcount 10 \
            -j DROP 2>/dev/null || true
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" \
            -j ACCEPT 2>/dev/null || true

        # 开放代理端口（IPv6）
        if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
            for port in "${OPEN_PORTS[@]}"; do
                ip6tables -A INPUT -p tcp --dport "$port" \
                    -j ACCEPT 2>/dev/null || true
                ip6tables -A INPUT -p udp --dport "$port" \
                    -j ACCEPT 2>/dev/null || true
            done
        fi

        # [A9 FIX] IPv6 FORWARD 同样只保留 ESTABLISHED,RELATED
        ip6tables -A FORWARD -m conntrack \
            --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

        # [C7 FIX] IPv6 DROP 前补 LOG 规则，与 IPv4 保持一致，便于排查拦截
        ip6tables -A INPUT -m limit --limit 5/min \
            -j LOG --log-prefix "[FW6-DROP] " --log-level 4 2>/dev/null || true
        ip6tables -A INPUT -j DROP 2>/dev/null || true
        ok "IPv6 防火墙规则已应用"
    else
        warn "ip6tables 未安装，跳过 IPv6 规则配置"
    fi

    # Docker 重启（清空 iptables 后必须重建 Docker 网络链）
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        info "重启 Docker 以重建容器网络规则..."
        systemctl restart docker 2>/dev/null \
            || service docker restart 2>/dev/null \
            || true
        ok "Docker 已重启，容器网络规则已重建"
    fi
}

# ============================================================
# save_rules: 持久化规则（IPv4 + IPv6）
# [A12 FIX] systemd 服务创建后使用 restart 而非 try-restart：
#   try-restart 的严格语义是"仅当服务处于 running 状态才重启"，
#   对 dead/failed/新建 状态一律跳过，首次运行时永远不会被拉起。
#   restart 无论当前状态如何都强制启动，行为符合预期。
# ============================================================
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0
    mkdir -p /etc/iptables

    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi

    if command -v netfilter-persistent &>/dev/null; then
        # Debian/Ubuntu 推荐方式（iptables-persistent 包提供）
        netfilter-persistent save &>/dev/null || true
    else
        # 动态查找路径，兼容不同发行版（/sbin / /usr/sbin / /usr/bin）
        local ipt_restore ip6t_restore
        ipt_restore=$(command -v iptables-restore 2>/dev/null \
            || echo "/usr/sbin/iptables-restore")
        ip6t_restore=$(command -v ip6tables-restore 2>/dev/null \
            || echo "/usr/sbin/ip6tables-restore")

        cat > /etc/systemd/system/iptables-restore.service << SVC
[Unit]
Description=Restore iptables rules (port.sh v${VERSION})
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target

[Service]
Type=oneshot
ExecStart=${ipt_restore} /etc/iptables/rules.v4
ExecStartPost=-${ip6t_restore} /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC
        systemctl daemon-reload &>/dev/null || true
        systemctl enable iptables-restore.service &>/dev/null || true
        # [A12 FIX] 使用 restart（非 try-restart）：
        # try-restart 在服务 dead/failed/未启动 时静默跳过，首次运行无效；
        # restart 无论当前状态一律强制启动。
        systemctl restart iptables-restore.service &>/dev/null || true
    fi
    ok "规则已保存，重启后自动生效"
}

# ============================================================
# show_status: 显示防火墙当前状态
# ============================================================
show_status() {
    hr; echo -e "${C}防火墙当前状态 (port.sh v${VERSION})${W}"; hr

    echo -e "${G}▸ IPv4 开放端口 (iptables INPUT ACCEPT):${W}"
    iptables -L INPUT -n 2>/dev/null \
        | grep ACCEPT | grep -oE 'dpts?:[0-9:]+' \
        | sort -u | sed 's/dpts\?:/  • /' || echo "  （无）"

    echo -e "\n${G}▸ 端口跳跃 (NAT PREROUTING DNAT):${W}"
    local has_nat=0
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local r t
        r=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+')
        t=$(echo "$line" \
            | grep -oE 'to:(\[::]\:|:)[0-9]+|to:[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+' \
            | grep -oE '[0-9]+$')
        [[ -n "$r" && -n "$t" ]] && echo "  • ${r//:/-} → :${t}" && has_nat=1
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
    [[ $has_nat -eq 0 ]] && echo "  （无）"

    echo -e "\n${G}▸ 公网监听端口 (ss -tulnp):${W}"
    while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"')
        printf "  • %-6s %s\n" "$p" "${proc:-(未知进程)}"
    done < <(get_public_ports)

    if command -v ip6tables &>/dev/null; then
        echo -e "\n${G}▸ IPv6 开放端口 (ip6tables INPUT ACCEPT):${W}"
        ip6tables -L INPUT -n 2>/dev/null \
            | grep ACCEPT | grep -oE 'dpts?:[0-9:]+' \
            | sort -u | sed 's/dpts\?:/  • /' || echo "  （无或未配置）"
    fi

    echo -e "\n${G}▸ 关键 sysctl 参数:${W}"
    for param in \
        net.ipv4.ip_forward \
        net.ipv6.conf.all.forwarding \
        net.ipv4.tcp_timestamps \
        net.ipv4.conf.all.rp_filter; do
        printf "  • %-45s = %s\n" "$param" \
            "$(sysctl -n "$param" 2>/dev/null || echo '未知')"
    done

    echo -e "\n${G}▸ 防火墙前端状态:${W}"
    printf "  • %-20s %s\n" "firewalld:" \
        "$(systemctl is-active firewalld 2>/dev/null || echo '未运行/未安装')"
    printf "  • %-20s %s\n" "ufw:" \
        "$(systemctl is-active ufw 2>/dev/null || echo '未运行/未安装')"
    if command -v docker &>/dev/null; then
        printf "  • %-20s %s\n" "docker:" \
            "$(systemctl is-active docker 2>/dev/null || echo '未知')"
    fi
    hr
}

# ============================================================
# reset_fw: 重置防火墙为全部放行
# ============================================================
reset_fw() {
    echo -e "${R}⚠  清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
    iptables -F; iptables -X
    iptables -t nat -F; iptables -t nat -X; iptables -t mangle -F

    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
        ip6tables -F; ip6tables -X
        ip6tables -t nat    -F 2>/dev/null || true
        ip6tables -t nat    -X 2>/dev/null || true
        ip6tables -t mangle -F 2>/dev/null || true
    fi

    save_rules
    # [C4 FIX] iptables -t nat -F 会清空 Docker 依赖的 NAT 链，
    # 导致所有带端口映射的容器瞬间断网。重置后必须重启 Docker 重建网络。
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        info "正在重启 Docker 以恢复容器网络映射..."
        systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || true
        ok "Docker 已重启，容器网络已恢复"
    fi
    ok "防火墙已重置为全部放行（IPv4 + IPv6）"
}

# ============================================================
# add_hop_interactive: 手动交互式添加端口跳跃
# [C3 FIX] 原实现直接调用 apply_hop，用 -A INPUT 追加规则；
#   但主流程结束后 INPUT 末尾已有 DROP，追加的 ACCEPT 永远不会命中。
#   修复：将规则加入内存数组后，重新执行完整的 detect → apply_rules 流程。
# ============================================================
add_hop_interactive() {
    # 确保依赖和内核模块就位（--add-hop 独立运行时跳过了主流程的 install_deps）
    install_deps
    detect_ssh
    hr; echo -e "${C}手动添加 Hysteria2 端口跳跃规则${W}"; hr
    echo -e "${Y}说明: 端口跳跃将多个外部端口的流量 DNAT 到代理实际监听端口${W}"
    echo -e "${Y}示例: 外部 20000-50000 → 内部 :443${W}"
    echo
    read -rp "跳跃端口范围（如 20000-50000）: " hop_range
    read -rp "目标端口（代理实际监听端口，如 443）: " target_port

    # [v4.6 FIX] 优化验证顺序：先验证格式，再提取数值
    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] \
        || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] \
        || err "目标端口格式错误，必须是数字"
    [[ "$target_port" -ge 1 && "$target_port" -le 65535 ]] \
        || err "目标端口超出范围 (1-65535)"

    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    
    # [v4.5 FIX] 完整的端口范围验证
    # [v4.6 FIX] 格式已在上面验证，这里只需验证数值范围
    [[ "$s" -ge 1 && "$s" -le 65535 ]] || err "起始端口超出范围 (1-65535)"
    [[ "$e" -ge 1 && "$e" -le 65535 ]] || err "结束端口超出范围 (1-65535)"
    [[ "$s" -lt "$e" ]] || err "起始端口必须小于结束端口"
    
    # 检查范围大小（防止性能问题）
    local range_size=$((e - s + 1))
    [[ "$range_size" -le 50000 ]] || err "端口范围过大 ($range_size 个端口)，建议不超过 50000"
    
    # 检查目标端口是否在跳跃范围内（会导致死循环）
    [[ "$target_port" -lt "$s" || "$target_port" -gt "$e" ]] \
        || err "目标端口 $target_port 不能在跳跃范围 $s-$e 内（会导致死循环）"
    
    [[ "$s" -ge 1024 ]] || warn "起始端口 < 1024，可能与系统端口冲突"

    # [C3 FIX] 将新规则加入内存，重新执行完整检测+构建流程
    # 这样可确保新 ACCEPT 规则插入在末尾 DROP 之前，而非之后
    HOP_RULES+=("${s}-${e}->${target_port}")
    add_port "$target_port"   # [C1/C2 FIX] 目标端口必须在 OPEN_PORTS 里

    info "正在重新构建防火墙规则（确保新跳跃规则位于 DROP 之前）..."
    detect_existing_hop_rules  # 重新拉取已有规则（去重）
    detect_hysteria_hop        # 补充 Hysteria2 配置文件里的跳跃
    detect_ports               # 重新扫描所有开放端口
    add_port 80
    add_port 443
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un) || true
    fi

    apply_rules
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 添加完成并已生效"
    echo -e "${C}验证: iptables -t nat -L PREROUTING -n | grep DNAT${W}"
    echo -e "${C}验证: ip6tables -t nat -L PREROUTING -n | grep DNAT${W}"
}

# ============================================================
# show_summary: 最终汇总输出
# ============================================================
show_summary() {
    hr; echo -e "${G}🎉 防火墙配置完成！（port.sh v${VERSION}）${W}"; hr

    echo -e "${C}SSH 端口  :${W} $SSH_PORT  ${Y}（防暴力破解: 60秒内限10次连接）${W}"
    echo -e "${C}开放端口  :${W} ${OPEN_PORTS[*]:-（无）}"

    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃  :${W}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            echo -e "  ${G}•${W} UDP+TCP ${HOP_S}-${HOP_E} → :${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置（Hysteria2 需要）"
        echo -e "  ${Y}如需手动添加: bash port.sh --add-hop${W}"
    fi

    hr
    echo -e "${Y}⚠  重要提示：${W}"
    echo -e "  ${R}▸ 云平台安全组（本机防火墙只是第一层）：${W}"
    echo    "    甲骨文: VCN → 安全列表 / NSG 入站规则"
    echo    "    AWS:    EC2 安全组 → Inbound Rules"
    echo    "    阿里云 / 腾讯云: 安全组规则"
    echo    "    以上需在云控制台单独放行端口，否则流量到达不了本机！"
    echo
    echo -e "  ${Y}▸ 面板管理端口安全建议：${W}"
    echo    "    X-UI (54321) / 3x-ui 面板建议通过 SSH 隧道访问："
    echo    "    ssh -L 54321:127.0.0.1:54321 root@服务器IP"
    echo    "    然后访问 http://127.0.0.1:54321（本地安全访问）"
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        echo -e "  ${G}▸ Docker 已自动重启并重建网络规则${W}"
    fi
    if command -v ip6tables &>/dev/null; then
        echo -e "  ${G}▸ IPv6 防火墙规则已同步配置（含 NDP 必要 ICMPv6）${W}"
    fi

    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态   : bash port.sh --status"
    echo "  手动加跳跃 : bash port.sh --add-hop"
    echo "  重置防火墙 : bash port.sh --reset"
    echo "  预览不改动 : bash port.sh --dry-run"
    echo "  查看IPv4   : iptables -L -n -v"
    echo "  查看NAT    : iptables -t nat -L -n -v"
    echo "  查看IPv6   : ip6tables -L -n -v"
    hr
}

# ============================================================
# main
# ============================================================
main() {
    echo -e "${B}══════════════════════════════════════════${W}"
    echo -e "${G}    代理节点防火墙管理脚本 v${VERSION}${W}"
    echo -e "${B}══════════════════════════════════════════${W}"

    # ── 单功能模式 ──────────────────────────────────────────
    [[ $_status -eq 1 ]] && { detect_ssh; show_status;  exit 0; }
    [[ $_reset  -eq 1 ]] && { detect_ssh; reset_fw;     exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;      exit 0; }

    # ── 主流程 ─────────────────────────────────────────────
    install_deps
    detect_ssh

    # ① 先加载已有跳跃规则（add_port 会排除跳跃范围内的端口）
    detect_existing_hop_rules
    detect_hysteria_hop

    # ② 综合扫描端口（ss + 配置文件 + 数据库）
    detect_ports

    # 确保 80/443 始终开放（Web / HTTPS 基础需求）
    add_port 80
    add_port 443

    # 排序去重
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un) || true
    fi

    # ── 预览摘要 ─────────────────────────────────────────────
    echo
    info "即将开放端口 : ${OPEN_PORTS[*]:-（无）}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "端口跳跃配置 : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置，如需手动添加: bash port.sh --add-hop"
    fi
    echo

    # ── 应用规则 ─────────────────────────────────────────────
    apply_rules
    save_rules
    show_summary
}

main "$@"
