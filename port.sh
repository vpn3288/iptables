#!/bin/bash
# ============================================================
# iptables 防火墙管理脚本 v4.0
# 适用于 Xray / Sing-box / V2Ray / Hysteria2 等代理服务
# 支持 Ubuntu 22/24, Debian 11/12, CentOS/RHEL 8+
# 功能：自动端口检测 | SSH防暴力 | 端口跳跃NAT | 持久化
# 注意：运行时完全禁用 nftables，独占防火墙控制权
# ============================================================
set -uo pipefail

# ── 颜色 ────────────────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

# ── 全局变量 ────────────────────────────────────────────────
VERSION="4.0"
SSH_PORT=""
OPEN_PORTS=()
HOP_RULES=()   # 格式: "起始-结束->目标"  如 "20000-50000->443"
DRY_RUN=false

EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|named|unbound|ntpd|avahi"

BLACKLIST_PORTS=(23 25 53 69 111 135 137 138 139 445 514 631
    110 143 465 587 993 995
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902 323 2049
    8181 9090 3000 3001 8000 8001 54321 62789
    10080 10081 10082 10083 10084 10085 10086)

# ── 参数解析 ────────────────────────────────────────────────
_status=0 _reset=0 _addhop=0
for arg in "$@"; do case "$arg" in
    --dry-run)  DRY_RUN=true ;;
    --status)   _status=1 ;;
    --reset)    _reset=1 ;;
    --add-hop)  _addhop=1 ;;
    --help|-h)
        echo "用法: bash iptables_fw.sh [--dry-run|--status|--reset|--add-hop|--help]"
        echo "  (无参数)   交互式完整配置"
        echo "  --status   查看当前规则和端口"
        echo "  --reset    清空所有规则（全部放行）"
        echo "  --add-hop  手动添加端口跳跃规则"
        echo "  --dry-run  预览模式，不实际修改"
        exit 0 ;;
    *) err "未知参数: $arg" ;;
esac; done

# ============================================================
# 工具函数
# ============================================================

get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | while read -r p; do [[ "$p" -lt 32768 ]] && echo "$p" || true; done \
        | sort -un || true
}

parse_hop() {
    local rule=$1
    HOP_S=$(echo "$rule" | cut -d'-' -f1)
    HOP_E=$(echo "$rule" | cut -d'-' -f2 | cut -d'>' -f1 | tr -d '>')
    HOP_T=$(echo "$rule" | grep -oE '[0-9]+$')
}

port_in_hop_range() {
    local p=$1
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    for b in "${BLACKLIST_PORTS[@]}"; do [[ "$p" == "$b" ]] && return 0; done
    return 1
}

add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]             || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                 && return 0
    port_in_hop_range "$p"             && return 0
    [[ " ${OPEN_PORTS[*]:-} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

# ============================================================
# 初始化：禁用 nftables + 安装 iptables + sysctl
# ============================================================
install_deps() {
    info "检查依赖..."

    # ── 完全禁用 nftables ────────────────────────────────────
    info "禁用 nftables..."
    systemctl stop    nftables &>/dev/null || true
    systemctl disable nftables &>/dev/null || true
    systemctl mask    nftables &>/dev/null || true
    # 清空 nftables 规则（防止残留规则继续生效）
    if command -v nft &>/dev/null; then
        nft flush ruleset 2>/dev/null || true
    fi
    # 清空 nftables 配置文件
    [[ -f /etc/nftables.conf ]] && > /etc/nftables.conf
    ok "nftables 已完全禁用"

    # ── 禁用其他冲突防火墙 ───────────────────────────────────
    for svc in ufw firewalld; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            systemctl stop    "$svc" &>/dev/null || true
            systemctl disable "$svc" &>/dev/null || true
            systemctl mask    "$svc" &>/dev/null || true
            ok "已禁用 $svc"
        fi
    done

    # ── 安装 iptables ────────────────────────────────────────
    local pkgs=()
    command -v iptables      &>/dev/null || pkgs+=(iptables)
    command -v iptables-save &>/dev/null || pkgs+=(iptables)
    command -v ss            &>/dev/null || pkgs+=(iproute2)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y iptables iptables-services iproute 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y iptables iptables-services iproute 2>/dev/null || true
        fi
        command -v iptables &>/dev/null || err "iptables 安装失败，请手动安装"
    fi

    # ── 确保 iptables 使用 legacy 模式（非 nft 后端）────────
    # Ubuntu 22/24 默认 iptables 可能指向 nft 后端，需切换为 legacy
    if command -v update-alternatives &>/dev/null; then
        update-alternatives --set iptables  /usr/sbin/iptables-legacy  &>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy &>/dev/null || true
        ok "iptables 已切换为 legacy 模式"
    fi

    # ── sysctl 参数 ──────────────────────────────────────────
    cat > /etc/sysctl.d/98-iptables-fw.conf << 'EOF'
# iptables_fw.sh v4.0 写入
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
# tcp_timestamps=0：防信息泄露
net.ipv4.tcp_timestamps=0
# rp_filter=2：宽松模式，兼容端口跳跃 UDP 转发（=1严格会丢包）
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-iptables-fw.conf &>/dev/null || true
    ok "依赖检查完成，sysctl 已配置"
}

detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=$(awk '/^Port /{print $2;exit}' /etc/ssh/sshd_config 2>/dev/null || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ============================================================
# 端口跳跃检测
# ============================================================
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        [[ -n "$range" && -n "$target" ]] || continue
        local rule="${range}->${target}"
        [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
}

detect_hysteria_hop() {
    local dirs=(/etc/hysteria /etc/hysteria2 /usr/local/etc/hysteria)
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for ext in json yaml yml; do
            local f="${d}/config.${ext}"
            [[ -f "$f" ]] || continue
            local listen_port="" hop_range=""
            if [[ "$ext" == "json" ]]; then
                listen_port=$(grep -oE '"listen"[^:]*:[^"]*":[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -oE '"(portHopping|portRange)"[^:]*:"[0-9]+-[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] \
                    || { HOP_RULES+=("$rule"); ok "检测到 Hysteria2 跳跃: $hop_range → $listen_port"; }
            fi
        done
    done
}

# ============================================================
# 端口检测：ss为主 + 配置文件补充
# ============================================================
detect_ports() {
    info "扫描公网监听端口..."

    while read -r port; do add_port "$port"; done < <(get_public_ports)

    # Python 解析 JSON 配置文件
    local py_parser="/tmp/_fw_parse_ports.py"
    cat > "$py_parser" << 'PYEOF'
import json, sys
def extract(data):
    ports, LOCAL = [], ('127.','::1','localhost')
    is_local = lambda v: any(str(v or '').startswith(x) for x in LOCAL)
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('port','listen_port'):
            p = inb.get(key)
            if isinstance(p,int) and 1<=p<=65535 and not is_local(inb.get('listen','')):
                ports.append(p)
    for src in [data.get('inbound')] + list(data.get('inboundDetour') or []):
        if not isinstance(src, dict): continue
        p = src.get('port')
        if isinstance(p,int) and 1<=p<=65535 and not is_local(src.get('listen','')):
            ports.append(p)
    return sorted(set(ports))
for f in sys.argv[1:]:
    try:
        with open(f) as fp: [print(p) for p in extract(json.load(fp))]
    except: pass
PYEOF

    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray /etc/xray
        /usr/local/etc/v2ray /etc/v2ray
        /etc/sing-box /opt/sing-box /usr/local/etc/sing-box
        /etc/v2ray-agent/xray/conf /etc/v2ray-agent/sing-box/conf
        /etc/hysteria /etc/hysteria2 /etc/tuic /etc/trojan
        /etc/x-ui /opt/3x-ui/bin /usr/local/x-ui/bin
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/config.json "$d"/*.json "$d"/conf/*.json "$d"/confs/*.json; do
            [[ -f "$f" ]] && cfg_files+=("$f")
        done
    done

    if [[ ${#cfg_files[@]} -gt 0 ]]; then
        while read -r port; do add_port "$port"
        done < <(python3 "$py_parser" "${cfg_files[@]}" 2>/dev/null | sort -un || true)
    fi

    # 233boy / v2ray-agent 文件名端口兜底
    for d in /etc/xray/conf /etc/xray/confs /usr/local/etc/xray/conf \
              /usr/local/etc/xray/confs /etc/v2ray-agent/xray/conf; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local fname_port
            fname_port=$(basename "$f" | grep -oE '[0-9]+\.json$' | grep -oE '[0-9]+' || true)
            [[ -n "$fname_port" ]] && add_port "$fname_port"
        done
    done
}

# ============================================================
# 应用 iptables 规则
# ============================================================
apply_hop() {
    local s=$1 e=$2 t=$3
    # 清除重复规则
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep "dpts:${s}:${e}" | awk '{print $1}' | sort -rn || true)
    for n in $nums; do iptables -t nat -D PREROUTING "$n" 2>/dev/null || true; done
    # NAT 转发
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    # INPUT 放行（幂等）
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT
}

flush_rules() {
    info "清理旧规则..."
    iptables  -P INPUT   ACCEPT 2>/dev/null || true
    iptables  -P FORWARD ACCEPT 2>/dev/null || true
    iptables  -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables  -F 2>/dev/null || true
    iptables  -X 2>/dev/null || true
    iptables  -t nat    -F 2>/dev/null || true
    iptables  -t nat    -X 2>/dev/null || true
    iptables  -t mangle -F 2>/dev/null || true
    iptables  -t raw    -F 2>/dev/null || true
    ip6tables -P INPUT   ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true
}

apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        hr; info "[预览模式] 以下规则不会实际应用"
        info "SSH 端口 : $SSH_PORT"
        info "开放端口 : ${OPEN_PORTS[*]:-无}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"; info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        hr; return 0
    fi

    flush_rules
    info "应用 iptables 规则..."

    # 默认策略
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    # 基础规则
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP（限速）
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # SSH 防暴力破解（recent 模块：60秒内超过6次新连接则丢弃）
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m conntrack --ctstate NEW \
        -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m conntrack --ctstate NEW \
        -m recent --name SSH_BF --update --seconds 60 --hitcount 6 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 代理端口（TCP + UDP）
    for port in "${OPEN_PORTS[@]:-}"; do
        [[ -z "$port" ]] && continue
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done

    # FORWARD（NAT 端口跳跃必需）
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT

    # 端口跳跃 NAT
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"
        [[ -z "${HOP_S:-}" || -z "${HOP_E:-}" || -z "${HOP_T:-}" ]] && continue
        apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
        ok "端口跳跃已应用: ${HOP_S}-${HOP_E} → ${HOP_T}"
    done

    # 兜底日志+丢弃
    iptables -A INPUT -m limit --limit 5/min -j LOG \
        --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP

    ok "iptables 规则已应用"
}

# ============================================================
# 持久化
# ============================================================
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    # 优先用 netfilter-persistent
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null || true
        ok "规则已通过 netfilter-persistent 保存"
        return 0
    fi

    # 备用：自定义 systemd 服务
    cat > /etc/systemd/system/iptables-restore.service << 'SVC'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecReload=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload  &>/dev/null || true
    systemctl enable iptables-restore.service &>/dev/null || true
    ok "规则已保存至 /etc/iptables/rules.v4，开机自动恢复"
}

# ============================================================
# 手动添加端口跳跃
# ============================================================
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加端口跳跃规则${W}"; hr
    read -rp "$(echo -e "${Y}端口范围（如 20000-50000）: ${W}")" hop_range
    read -rp "$(echo -e "${Y}目标端口（代理实际监听端口）: ${W}")" target_port
    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] || err "目标端口格式错误"
    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -ge "$e" ]] && err "起始端口须小于结束端口"
    apply_hop "$s" "$e" "$target_port"
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 添加完成"
}

# ============================================================
# 显示状态
# ============================================================
show_status() {
    hr; echo -e "${C}防火墙当前状态${W}"; hr

    echo -e "${G}▸ 开放端口 (iptables INPUT):${W}"
    iptables -L INPUT -n 2>/dev/null \
        | grep ACCEPT \
        | grep -oE 'dpts?:[0-9:]+' \
        | sort -u \
        | sed 's/dpts\?:/  • /' || echo "  无"

    echo -e "\n${G}▸ 端口跳跃 (NAT PREROUTING):${W}"
    local has_nat=0
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local r t
        r=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+')
        t=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        [[ -n "$r" && -n "$t" ]] && echo "  • ${r//:/-} → :${t}" && has_nat=1
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
    [[ $has_nat -eq 0 ]] && echo "  无"

    echo -e "\n${G}▸ 公网监听端口 (ss):${W}"
    get_public_ports | while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
        printf "  • %-6s %s\n" "$p" "${proc:-(未知)}"
    done

    echo -e "\n${G}▸ 关键 sysctl 参数:${W}"
    for param in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.tcp_timestamps; do
        printf "  • %-45s = %s\n" "$param" "$(sysctl -n "$param" 2>/dev/null || echo 未知)"
    done

    echo -e "\n${G}▸ nftables 状态（应为禁用）:${W}"
    systemctl is-active nftables &>/dev/null \
        && warn "nftables.service 仍在运行！请检查" \
        || ok   "nftables.service 已禁用"

    echo -e "\n${G}▸ iptables 后端:${W}"
    if command -v iptables &>/dev/null; then
        local backend
        backend=$(iptables --version 2>/dev/null | head -1)
        echo "  • $backend"
        [[ "$backend" == *"legacy"* ]] && ok "使用 legacy 后端（正确）" \
            || warn "可能使用 nft 后端，建议切换: update-alternatives --set iptables /usr/sbin/iptables-legacy"
    fi
    hr
}

# ============================================================
# 重置
# ============================================================
do_reset() {
    echo -e "${R}⚠ 清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }
    iptables  -P INPUT   ACCEPT
    iptables  -P FORWARD ACCEPT
    iptables  -P OUTPUT  ACCEPT
    iptables  -F; iptables  -X
    iptables  -t nat    -F; iptables -t nat    -X
    iptables  -t mangle -F; iptables -t mangle -X
    ip6tables -P INPUT   ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    save_rules
    ok "防火墙已重置，所有流量放行"
}

# ============================================================
# 摘要
# ============================================================
show_summary() {
    hr; echo -e "${G}🎉 防火墙配置完成！${W}"; hr
    echo -e "${C}防火墙引擎 :${W} iptables legacy  ${G}（nftables 已禁用）${W}"
    echo -e "${C}SSH 端口   :${W} $SSH_PORT  ${Y}（防暴力破解已启用）${W}"
    echo -e "${C}开放端口   :${W} ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃   :${W}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"
            echo -e "  ${G}•${W} ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未配置端口跳跃  →  如需添加: bash iptables_fw.sh --add-hop"
    fi
    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态   : bash iptables_fw.sh --status"
    echo "  添加跳跃   : bash iptables_fw.sh --add-hop"
    echo "  重置防火墙 : bash iptables_fw.sh --reset"
    echo "  查看规则   : iptables -L -n -v"
    echo "  查看NAT    : iptables -t nat -L -n -v"
    hr
}

# ============================================================
# 主流程
# ============================================================
main() {
    trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM
    hr
    echo -e "${G}   iptables 防火墙管理脚本 v${VERSION}${W}"
    hr

    [[ $_status -eq 1 ]] && { detect_ssh; show_status;        exit 0; }
    [[ $_reset  -eq 1 ]] && { detect_ssh; do_reset;           exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;            exit 0; }

    install_deps
    detect_ssh

    # 先检测跳跃规则（端口过滤时排除跳跃范围）
    detect_existing_hop_rules
    detect_hysteria_hop

    detect_ports
    add_port 80; add_port 443

    mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]:-}" | sort -un) || true

    echo
    info "SSH 端口 : $SSH_PORT"
    info "开放端口 : ${OPEN_PORTS[*]:-无}"
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"; info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
    done
    [[ ${#HOP_RULES[@]} -eq 0 ]] && warn "未检测到端口跳跃  →  如需添加: bash iptables_fw.sh --add-hop"
    echo

    read -rp "$(echo -e "${Y}确认应用以上配置？[y/N]: ${W}")" ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }

    apply_rules
    save_rules
    show_summary
}

main "$@"
