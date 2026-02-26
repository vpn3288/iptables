#!/bin/bash
set -uo pipefail
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

SSH_PORT="" OPEN_PORTS=() HOP_RULES=() VERSION="3.6" DRY_RUN=false
_status=0 _reset=0 _addhop=0

for arg in "$@"; do case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --status)  _status=1 ;;
    --reset)   _reset=1 ;;
    --add-hop) _addhop=1 ;;
    --help|-h) echo "用法: bash port.sh [--dry-run|--status|--reset|--add-hop|--help]"; exit 0 ;;
    *) err "未知参数: $arg" ;;
esac; done

# 不对外暴露的系统进程
EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd.resolve|named|unbound|ntpd|avahi"

# ===========================================================
# get_public_ports: ss 为权威，过滤 localhost + 系统进程 + 高位临时端口
# ===========================================================
get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | while read -r p; do [[ "$p" -lt 32768 ]] && echo "$p" || true; done \
        | sort -un || true
}

install_deps() {
    local pkgs=()
    command -v iptables &>/dev/null || pkgs+=(iptables)
    command -v ss       &>/dev/null || pkgs+=(iproute2)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        command -v apt-get &>/dev/null && apt-get update -qq && apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || true
        command -v yum     &>/dev/null && yum install -y -q "${pkgs[@]}" 2>/dev/null || true
    fi

    # ── ip_forward（端口跳跃 NAT 必须）────────────────────────────────
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null
    grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null \
        || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

    # ── 安全加固（不覆盖 youhua.sh 的性能参数）─────────────────────────
    sysctl -w net.ipv4.conf.all.send_redirects=0      &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0    &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true

    # ── tcp_timestamps：与 youhua.sh v2.4 统一为 0（关闭）──────────────
    # BBRplus 无需时间戳也能正常工作；关闭防止外部通过时间戳推算系统信息
    sysctl -w net.ipv4.tcp_timestamps=0 &>/dev/null || true

    # ── rp_filter=2 宽松模式：与 youhua.sh v2.4 保持一致 ───────────────
    # 原值 =1 严格模式会丢弃端口跳跃的 UDP 转发包，导致跳跃失效
    # =2 保留路径过滤安全性，同时允许 NAT 转发包通过
    sysctl -w net.ipv4.conf.all.rp_filter=2     &>/dev/null || true
    sysctl -w net.ipv4.conf.default.rp_filter=2 &>/dev/null || true

    # 持久化到独立文件，不污染其他脚本写入的 sysctl.conf
    cat > /etc/sysctl.d/98-port-firewall.conf << 'EOF'
# port.sh v3.6 写入
# 与 youhua.sh v2.4 / BBRplus 完全兼容
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
# tcp_timestamps=0：防信息泄露，与 youhua.sh v2.4 一致
net.ipv4.tcp_timestamps=0
# rp_filter=2：宽松反向路径过滤，兼容端口跳跃 NAT
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-port-firewall.conf &>/dev/null || true
    ok "sysctl 参数已写入 /etc/sysctl.d/98-port-firewall.conf"
}

detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

parse_hop() {
    local rule=$1
    HOP_S=$(echo "$rule" | cut -d'-' -f1)
    HOP_E=$(echo "$rule" | cut -d'-' -f2 | cut -d'>' -f1 | tr -d '>')
    HOP_T=$(echo "$rule" | grep -oE '[0-9]+$')
}

port_in_hop_range() {
    local p=$1
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    case "$p" in
        23|25|53|69|111|135|137|138|139|445|514|631) return 0;;
        110|143|465|587|993|995) return 0;;
        1433|1521|3306|5432|6379|27017) return 0;;
        3389|5900|5901|5902|323|2049) return 0;;
        8181|9090|3000|3001|8000|8001|54321|62789) return 0;;
        10080|10081|10082|10083|10084|10085|10086) return 0;;
    esac
    return 1
}

add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]             || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                 && return 0
    port_in_hop_range "$p"             && return 0
    [[ " ${OPEN_PORTS[*]} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        [[ -n "$range" && -n "$target" ]] || continue
        local rule="${range}->${target}"
        [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
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
                listen_port=$(grep -oE '"listen"[^:]*:[^"]*"[^"]*"' "$f" 2>/dev/null | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
                hop_range=$(grep -oE '"(portHopping|portRange)"[^:]*:[^"]*"[0-9]+-[0-9]+"' "$f" 2>/dev/null | grep -oE '[0-9]+-[0-9]+' | head -1)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null | grep -oE '[0-9]+-[0-9]+' | head -1)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] || { HOP_RULES+=("$rule"); ok "检测到 Hysteria2 跳跃: $hop_range → $listen_port"; }
            fi
        done
    done
}

# ===========================================================
# 端口扫描：ss 为主，配置文件为辅
# ===========================================================
detect_ports() {
    info "扫描公网监听端口..."

    # ── ss 扫描（最可靠，实际监听状态）──────────────────────
    while read -r port; do
        add_port "$port"
    done < <(get_public_ports)

    # ── 配置文件补充（覆盖未运行节点的端口）─────────────────
    local py_parser="/tmp/_fw_parse_ports.py"
    cat > "$py_parser" << 'PYEOF'
import json, sys

def extract_ports(data):
    ports = []
    LOCAL = ('127.', '::1', 'localhost')
    def is_local(v):
        return any(str(v or '').startswith(x) for x in LOCAL)
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('port', 'listen_port'):
            p = inb.get(key)
            if isinstance(p, int) and 1 <= p <= 65535 and not is_local(inb.get('listen','')):
                ports.append(p)
    for src in [data.get('inbound')] + list(data.get('inboundDetour') or []):
        if not isinstance(src, dict): continue
        p = src.get('port')
        if isinstance(p, int) and 1 <= p <= 65535 and not is_local(src.get('listen','')):
            ports.append(p)
    return sorted(set(ports))

for f in sys.argv[1:]:
    try:
        with open(f) as fp:
            data = json.load(fp)
        for p in extract_ports(data):
            print(p)
    except Exception:
        pass
PYEOF

    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray /etc/xray
        /usr/local/etc/v2ray /etc/v2ray
        /etc/sing-box /opt/sing-box /usr/local/etc/sing-box
        /etc/hysteria /etc/hysteria2
        /etc/tuic /etc/trojan
        /etc/x-ui /opt/3x-ui/bin /usr/local/x-ui/bin
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/config.json "$d"/*.json "$d"/conf/*.json "$d"/confs/*.json; do
            [[ -f "$f" ]] && cfg_files+=("$f")
        done
    done

    if [[ ${#cfg_files[@]} -gt 0 ]]; then
        while read -r port; do
            add_port "$port"
        done < <(python3 "$py_parser" "${cfg_files[@]}" 2>/dev/null | sort -un || true)
    fi

    # ── 233boy 文件名端口兜底 ────────────────────────────────
    local conf_dirs=(/etc/xray/conf /etc/xray/confs /usr/local/etc/xray/conf /usr/local/etc/xray/confs)
    for d in "${conf_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local fname_port
            fname_port=$(basename "$f" | grep -oE '[0-9]+\.json$' | grep -oE '[0-9]+')
            [[ -z "$fname_port" ]] && continue
            add_port "$fname_port"
        done
    done
}

apply_hop() {
    local s=$1 e=$2 t=$3
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep "dpts:${s}:${e}" | awk '{print $1}' | sort -rn)
    for n in $nums; do iptables -t nat -D PREROUTING "$n" 2>/dev/null || true; done
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT
}

flush_rules() {
    info "清理旧规则..."
    iptables -P INPUT   ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables -F 2>/dev/null || true; iptables -X 2>/dev/null || true
    iptables -t nat    -F 2>/dev/null || true; iptables -t nat    -X 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
}

apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        info "[预览] 开放端口: ${OPEN_PORTS[*]:-无}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"; info "[预览] 端口跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        return 0
    fi
    flush_rules
    iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP
    # SSH 防暴力破解
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m recent --name SSH_BF --update --seconds 60 --hitcount 6 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    # 开放代理端口
    for port in "${OPEN_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done
    # FORWARD（NAT 必需）
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT
    # 端口跳跃
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ -n "$HOP_S" && -n "$HOP_E" && -n "$HOP_T" ]] || continue
        apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
        ok "端口跳跃已应用: ${HOP_S}-${HOP_E} → ${HOP_T}"
    done
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP
}

save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null || true
    else
        cat > /etc/systemd/system/iptables-restore.service << 'SVC'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SVC
        systemctl daemon-reload &>/dev/null || true
        systemctl enable iptables-restore.service &>/dev/null || true
    fi
    ok "规则已保存，重启后自动生效"
}

show_status() {
    hr; echo -e "${C}防火墙当前状态${W}"; hr
    echo -e "${G}▸ 开放端口 (iptables):${W}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -oE 'dpts?:[0-9:]+' | sort -u | sed 's/dpts\?:/  • /' || true

    echo -e "\n${G}▸ 端口跳跃 (NAT):${W}"
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
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" | grep -oE '"[^"]+"' | head -1 | tr -d '"')
        printf "  • %-6s %s\n" "$p" "${proc:-(未知)}"
    done

    echo -e "\n${G}▸ 关键 sysctl 参数:${W}"
    for param in net.ipv4.tcp_timestamps net.ipv4.conf.all.rp_filter net.ipv4.ip_forward; do
        printf "  • %-45s = %s\n" "$param" "$(sysctl -n $param 2>/dev/null || echo '未知')"
    done
    hr
}

reset_fw() {
    echo -e "${R}⚠ 清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }
    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
    iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X; iptables -t mangle -F
    save_rules; ok "防火墙已重置为全部放行"
}

add_hop_interactive() {
    detect_ssh; hr; echo -e "${C}手动添加端口跳跃规则${W}"; hr
    read -rp "端口范围（如 20000-50000）: " hop_range
    read -rp "目标端口（代理实际监听端口）: " target_port
    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] || err "目标端口格式错误"
    local s e
    s=$(echo "$hop_range" | cut -d- -f1); e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -ge "$e" ]] && err "起始端口须小于结束端口"
    apply_hop "$s" "$e" "$target_port"
    save_rules; ok "端口跳跃 ${hop_range} → ${target_port} 添加完成"
}

show_summary() {
    hr; echo -e "${G}🎉 防火墙配置完成！${W}"; hr
    echo -e "${C}SSH 端口 :${W} $SSH_PORT  ${Y}（防暴力破解已启用）${W}"
    echo -e "${C}开放端口 :${W} ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃 :${W}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"; echo -e "  ${G}•${W} ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置"
        echo -e "  ${Y}如需添加: bash port.sh --add-hop${W}"
    fi
    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态   : bash port.sh --status"
    echo "  手动加跳跃 : bash port.sh --add-hop"
    echo "  重置防火墙 : bash port.sh --reset"
    echo "  查看规则   : iptables -L -n -v"
    echo "  查看NAT    : iptables -t nat -L -n -v"
    hr
}

main() {
    trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM
    echo -e "${B}══════════════════════════════════════════${W}"
    echo -e "${G}   代理节点防火墙管理脚本 v${VERSION}${W}"
    echo -e "${B}══════════════════════════════════════════${W}"

    [[ $_status -eq 1 ]] && { detect_ssh; show_status; exit 0; }
    [[ $_reset  -eq 1 ]] && { detect_ssh; reset_fw;    exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;     exit 0; }

    install_deps
    detect_ssh

    # ① 先检测跳跃规则（用于后续端口过滤）
    detect_existing_hop_rules
    detect_hysteria_hop

    # ② 扫描端口（ss 为主，配置文件补充）
    detect_ports

    # 确保 80/443
    add_port 80; add_port 443

    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un) || true
    fi

    echo
    info "开放端口 : ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do parse_hop "$rule"; info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"; done
    else
        warn "未检测到端口跳跃配置，如需手动添加: bash port.sh --add-hop"
    fi
    echo

    apply_rules
    save_rules
    show_summary
}

main "$@"
