#!/bin/bash
# ============================================================
# 代理节点防火墙自动管理脚本 v3.1
# 支持: Hiddify / 3X-UI / X-UI / Sing-box / Xray / V2Ray
#       fscarhem / v2ray-agent / Hysteria2 端口跳跃
# 使用: bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh)
# ============================================================
set -euo pipefail

R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

SSH_PORT=""
OPEN_PORTS=()
HOP_RULES=()
VERSION="3.1"
DRY_RUN=false
_status=0 _reset=0 _addhop=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=true ;;
        --status)   _status=1 ;;
        --reset)    _reset=1 ;;
        --add-hop)  _addhop=1 ;;
        --help|-h)  echo "用法: bash port.sh [--dry-run|--status|--reset|--add-hop|--help]"; exit 0 ;;
        *) err "未知参数: $arg" ;;
    esac
done

# ── 安装依赖 + 系统隐蔽优化 ─────────────────────────────────
install_deps() {
    local pkgs=()
    command -v iptables &>/dev/null || pkgs+=(iptables)
    command -v ss       &>/dev/null || pkgs+=(iproute2)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq "${pkgs[@]}" 2>/dev/null
        elif command -v yum &>/dev/null; then
            yum install -y -q "${pkgs[@]}" 2>/dev/null
        fi
    fi
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null
    grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null \
        || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.send_redirects=0      &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0    &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true
    sysctl -w net.ipv4.tcp_timestamps=0               &>/dev/null || true
}

# ── 检测 SSH 端口 ────────────────────────────────────────────
detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null \
        | awk '/sshd/{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' | head -1)
    [[ -z "$SSH_PORT" ]] && \
        SSH_PORT=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ── 解析跳跃规则字符串 "s-e->t" ─────────────────────────────
parse_hop() {
    # 格式: 16820-16999->16801
    local rule=$1
    HOP_S=$(echo "$rule" | awk -F'[-]' '{print $1}')
    HOP_E=$(echo "$rule" | awk -F'[-]' '{print $2}' | awk -F'->' '{print $1}')
    HOP_T=$(echo "$rule" | awk -F'->' '{print $2}')
}

# ── 判断端口是否在某个跳跃范围内 ────────────────────────────
port_in_hop_range() {
    local p=$1
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

# ── 黑名单判断 ───────────────────────────────────────────────
is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    local bl=(23 25 53 69 111 135 137 138 139 445 514 631
              110 143 465 587 993 995
              1433 1521 3306 5432 6379 27017
              3389 5900 5901 5902
              8181 9090 3000 3001 8000 8001 54321 62789
              10080 10081 10082 10083 10084 10085 10086)
    for b in "${bl[@]}"; do [[ "$p" == "$b" ]] && return 0; done
    return 1
}

# ── 安全添加端口到列表 ───────────────────────────────────────
add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]               || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]]   || return 0
    is_blacklisted "$p"                   && return 0
    port_in_hop_range "$p"               && return 0  # 跳跃范围内不单独开放
    [[ " ${OPEN_PORTS[*]} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

# ── 从 NAT 表检测已有跳跃规则 ───────────────────────────────
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" =~ DNAT ]] || continue
        local range target
        range=$(echo "$line"  | grep -oE 'dpts:[0-9]+:[0-9]+' \
            | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        if [[ -n "$range" && -n "$target" ]]; then
            local rule="${range}->${target}"
            [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
        fi
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null)
}

# ── 从 Hysteria2 配置文件检测跳跃设置 ───────────────────────
detect_hysteria_hop() {
    local dirs=(/etc/hysteria /etc/hysteria2 /usr/local/etc/hysteria)
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for ext in json yaml yml; do
            local f="${d}/config.${ext}"
            [[ -f "$f" ]] || continue
            local listen_port="" hop_range=""
            if [[ "$ext" == "json" ]]; then
                listen_port=$(grep -oE '"listen"\s*:\s*"[^"]*"' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | tr -d ':' | head -1)
                hop_range=$(grep -oE '"(portHopping|portRange)"\s*:\s*"[0-9]+-[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | tr -d ':' | head -1)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                if [[ ! " ${HOP_RULES[*]} " =~ " ${rule} " ]]; then
                    HOP_RULES+=("$rule")
                    ok "自动检测到 Hysteria2 端口跳跃: $hop_range → $listen_port"
                fi
            fi
        done
    done
}

# ── 扫描监听端口 ─────────────────────────────────────────────
detect_listening_ports() {
    info "扫描监听端口..."
    while read -r port; do
        add_port "$port"
    done < <(ss -tlunp 2>/dev/null \
        | awk 'NR>1{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' \
        | sort -un)
}

# ── 扫描配置文件端口 ─────────────────────────────────────────
detect_config_ports() {
    local configs=(
        /etc/x-ui/config.json
        /opt/3x-ui/bin/config.json
        /usr/local/x-ui/bin/config.json
        /usr/local/etc/xray/config.json  /etc/xray/config.json
        /usr/local/etc/v2ray/config.json /etc/v2ray/config.json
        /etc/sing-box/config.json        /opt/sing-box/config.json
        /usr/local/etc/sing-box/config.json
        /etc/hysteria/config.json        /etc/hysteria2/config.json
        /etc/tuic/config.json            /etc/trojan/config.json
        /opt/hiddify-manager/.env
    )
    for f in "${configs[@]}"; do
        [[ -f "$f" ]] || continue
        while read -r port; do
            add_port "$port"
        done < <(grep -oE '"port"\s*:\s*[0-9]+' "$f" 2>/dev/null \
            | grep -oE '[0-9]+' | sort -un)
    done
}

# ── 应用单条跳跃规则（幂等）────────────────────────────────
apply_hop() {
    local s=$1 e=$2 t=$3
    # 删除同范围旧规则
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | awk "/dpts:${s}:${e}/{print \$1}" | sort -rn)
    for n in $nums; do
        iptables -t nat -D PREROUTING "$n" 2>/dev/null || true
    done
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}"
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}"
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT
}

# ── 清空旧规则 ───────────────────────────────────────────────
flush_rules() {
    info "清理旧规则..."
    for chain in INPUT FORWARD OUTPUT; do
        iptables -P "$chain" ACCEPT 2>/dev/null || true
    done
    iptables -F            2>/dev/null || true
    iptables -X            2>/dev/null || true
    iptables -t nat    -F  2>/dev/null || true
    iptables -t nat    -X  2>/dev/null || true
    iptables -t mangle -F  2>/dev/null || true
}

# ── 应用全部防火墙规则 ───────────────────────────────────────
apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        echo
        info "[预览] 开放端口 : ${OPEN_PORTS[*]:-无}"
        if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
            for rule in "${HOP_RULES[@]}"; do
                parse_hop "$rule"
                info "[预览] 端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
            done
        fi
        return 0
    fi

    flush_rules

    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP 限速（不完全屏蔽，防止暴露异常特征）
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # SSH 防暴力破解
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH_BF --update --seconds 60 --hitcount 6 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 开放代理端口
    for port in "${OPEN_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done

    # FORWARD 放行（NAT 必需）
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT

    # 端口跳跃规则（自动应用，无需询问）
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ -n "$HOP_S" && -n "$HOP_E" && -n "$HOP_T" ]] || continue
        apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
        ok "端口跳跃已应用: ${HOP_S}-${HOP_E} → ${HOP_T}"
    done

    # 丢弃其余流量（限速日志）
    iptables -A INPUT -m limit --limit 5/min \
        -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP
}

# ── 保存规则（开机自动恢复）────────────────────────────────
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null || true
    else
        cat > /etc/systemd/system/iptables-restore.service <<'SVC'
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
        systemctl daemon-reload  &>/dev/null || true
        systemctl enable iptables-restore.service &>/dev/null || true
    fi
    ok "规则已保存，重启后自动生效"
}

# ── 显示状态 ─────────────────────────────────────────────────
show_status() {
    hr
    echo -e "${C}防火墙当前状态${W}"
    hr
    echo -e "${G}▸ 开放端口:${W}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT \
        | grep -oE 'dpts?:[0-9:]+' \
        | sed 's/dpts\?:/  • /' || true
    echo -e "\n${G}▸ 端口跳跃 (NAT):${W}"
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep DNAT \
        | awk '{for(i=1;i<=NF;i++){if($i~/dpts:/)r=$i; if($i~/to:/)t=$i}
                if(r&&t) printf "  • %s → %s\n",r,t}' || true
    echo -e "\n${G}▸ 进程监听:${W}"
    ss -tlunp 2>/dev/null | awk 'NR>1{
        match($4,/:([0-9]+)$/,a)
        if(a[1]) printf "  • %-5s %s\n",$1,$4
    }' | sort -u
    hr
}

# ── 重置防火墙 ───────────────────────────────────────────────
reset_fw() {
    echo -e "${R}⚠ 清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }
    for chain in INPUT FORWARD OUTPUT; do iptables -P "$chain" ACCEPT; done
    iptables -F; iptables -X
    iptables -t nat    -F; iptables -t nat    -X
    iptables -t mangle -F
    save_rules
    ok "防火墙已重置为全部放行"
}

# ── 手动添加跳跃规则 ────────────────────────────────────────
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加端口跳跃规则${W}"; hr
    read -rp "端口范围（如 20000-50000）: " hop_range
    read -rp "目标端口（代理实际监听端口）: " target_port
    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] || err "范围格式错误，应为: 起始-结束"
    [[ "$target_port" =~ ^[0-9]+$         ]] || err "目标端口格式错误"
    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -ge "$e" ]] && err "起始端口须小于结束端口"
    apply_hop "$s" "$e" "$target_port"
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 添加完成"
}

# ── 显示最终汇总 ─────────────────────────────────────────────
show_summary() {
    hr
    echo -e "${G}🎉 防火墙配置完成！${W}"
    hr
    echo -e "${C}SSH 端口 :${W} $SSH_PORT  ${Y}（防暴力破解已启用）${W}"
    echo -e "${C}开放端口 :${W} ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃 :${W}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            echo -e "  ${G}•${W} ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置"
        echo -e "  ${Y}如需添加，运行: bash port.sh --add-hop${W}"
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

# ── 主流程 ───────────────────────────────────────────────────
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

    # ② 再扫描端口（跳跃范围内的自动过滤）
    detect_listening_ports
    detect_config_ports

    add_port 80
    add_port 443

    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un)
    fi

    echo
    info "开放端口 : ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}（自动应用）"
        done
    else
        warn "未检测到端口跳跃配置，如需手动添加: bash port.sh --add-hop"
    fi
    echo

    apply_rules
    save_rules
    show_summary
}

main "$@"
