#!/bin/bash
# ============================================================
# 代理节点防火墙自动管理脚本 v3.4
# 支持: Hiddify / 3X-UI / X-UI / Sing-box / Xray / V2Ray
#       Hysteria2 端口跳跃 / fscarhem / v2ray-agent
# 使用: bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh)
# ============================================================
set -uo pipefail

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
VERSION="3.4"
DRY_RUN=false
_status=0 _reset=0 _addhop=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=true ;;
        --status)   _status=1 ;;
        --reset)    _reset=1 ;;
        --add-hop)  _addhop=1 ;;
        --help|-h)
            echo "用法: bash port.sh [--dry-run|--status|--reset|--add-hop|--help]"
            exit 0 ;;
        *) err "未知参数: $arg" ;;
    esac
done

# ═══════════════════════════════════════════════════════════
# 端口扫描
# 规则:
#   ① 只取绑定在公网地址的端口（排除 127.x 和 ::1）
#   ② 排除非代理系统进程（cloudflared/chronyd/dnsmasq 等）
#   ③ 只保留端口号 < 32768（临时端口范围不对外暴露）
#   ④ 配置文件里明确写的端口不受 ③ 限制
# ═══════════════════════════════════════════════════════════

# 不对外暴露的系统进程
EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd.resolve|named|unbound|ntpd|avahi"

get_public_ports() {
    # 只取公网绑定端口，排除 localhost + 系统进程 + 临时端口(>=32768)
    ss -tulnp 2>/dev/null \
        | grep -vE '(127\.|::1)' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | grep -v '^1$' \
        | sort -un \
        | while read -r p; do
            # 用 if 而非 && ，避免 set -e 把条件为假误判为错误
            if [[ "$p" -lt 32768 ]]; then echo "$p"; fi
        done || true
}

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
    # 隐蔽性内核参数
    sysctl -w net.ipv4.conf.all.send_redirects=0      &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0    &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true
    sysctl -w net.ipv4.tcp_timestamps=0               &>/dev/null || true
}

# ── 检测 SSH 端口 ────────────────────────────────────────────
detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd \
        | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
    [[ -z "$SSH_PORT" ]] && \
        SSH_PORT=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ── 解析跳跃规则 "s-e->t" ────────────────────────────────────
# 格式示例: 16820-16999->16801
parse_hop() {
    local rule=$1
    HOP_S=$(echo "$rule" | cut -d'-' -f1)
    HOP_E=$(echo "$rule" | cut -d'-' -f2 | cut -d'>' -f1 | tr -d '>')
    HOP_T=$(echo "$rule" | grep -oE '[0-9]+$')
}

# ── 端口是否在跳跃范围内 ─────────────────────────────────────
port_in_hop_range() {
    local p=$1
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

# ── 黑名单端口 ───────────────────────────────────────────────
is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    case "$p" in
        # 危险服务
        23|25|53|69|111|135|137|138|139|445|514|631) return 0 ;;
        110|143|465|587|993|995) return 0 ;;
        1433|1521|3306|5432|6379|27017) return 0 ;;
        3389|5900|5901|5902) return 0 ;;
        # 系统服务
        323|111|2049) return 0 ;;
        # 内部管理面板
        8181|9090|3000|3001|8000|8001|54321|62789) return 0 ;;
        10080|10081|10082|10083|10084|10085|10086) return 0 ;;
    esac
    return 1
}

# ── 安全添加端口 ─────────────────────────────────────────────
add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]               || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]]   || return 0
    is_blacklisted "$p"                   && return 0
    port_in_hop_range "$p"               && return 0
    [[ " ${OPEN_PORTS[*]} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

# ── 从 NAT 表读取已有跳跃规则 ───────────────────────────────
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' \
            | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        if [[ -n "$range" && -n "$target" ]]; then
            local rule="${range}->${target}"
            [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
        fi
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
}

# ── 从 Hysteria2 配置文件检测跳跃 ───────────────────────────
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
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
                hop_range=$(grep -oE '"(portHopping|portRange)"\s*:\s*"[0-9]+-[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                if [[ ! " ${HOP_RULES[*]} " =~ " ${rule} " ]]; then
                    HOP_RULES+=("$rule")
                    ok "检测到 Hysteria2 端口跳跃: $hop_range → $listen_port"
                fi
            fi
        done
    done
}

# ── 扫描监听端口 ─────────────────────────────────────────────
detect_listening_ports() {
    info "扫描公网监听端口（过滤 localhost/系统进程/临时端口）..."
    while read -r port; do
        add_port "$port"
    done < <(get_public_ports || true)
}

# ── 扫描配置文件端口（不受 32768 限制）───────────────────────
detect_config_ports() {
    # ── 固定配置文件路径 ──────────────────────────────────────
    local configs=(
        /usr/local/etc/xray/config.json  /etc/xray/config.json
        /usr/local/etc/v2ray/config.json /etc/v2ray/config.json
        /etc/x-ui/config.json            /opt/3x-ui/bin/config.json
        /usr/local/x-ui/bin/config.json
        /etc/sing-box/config.json        /opt/sing-box/config.json
        /usr/local/etc/sing-box/config.json
        /etc/hysteria/config.json        /etc/hysteria2/config.json
        /etc/tuic/config.json            /etc/trojan/config.json
        /opt/hiddify-manager/.env
    )

    # ── 233boy xray：扫描 conf 目录下所有 JSON ────────────────
    # 文件名格式: VLESS-Reality-12503.json，末尾数字即端口
    local conf_dirs=(/etc/xray/conf /etc/xray/confs /usr/local/etc/xray/conf /usr/local/etc/xray/confs)
    for d in "${conf_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            configs+=("$f")
            # 从文件名直接提取端口（233boy 命名规则）
            local fname_port
            fname_port=$(basename "$f" | grep -oE '[0-9]+\.json$' | grep -oE '[0-9]+')
            if [[ -n "$fname_port" ]]; then
                [[ "$fname_port" -ge 1 && "$fname_port" -le 65535 ]] || continue
                is_blacklisted "$fname_port"                  && continue
                port_in_hop_range "$fname_port"              && continue
                [[ " ${OPEN_PORTS[*]} " =~ " $fname_port " ]] && continue
                OPEN_PORTS+=("$fname_port")
            fi
        done
    done

    # ── 提取所有配置文件中的 "port": 数字 ────────────────────
    # 过滤掉 listen 在 127.x 的 inbound（内部端口）
    for f in "${configs[@]}"; do
        [[ -f "$f" ]] || continue
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]]                 || continue
            [[ "$port" -ge 1 && "$port" -le 65535 ]]  || continue
            is_blacklisted "$port"                     && continue
            port_in_hop_range "$port"                 && continue
            [[ " ${OPEN_PORTS[*]} " =~ " $port " ]]   && continue
            # 只检查同一行的 listen 地址，避免跨 inbound 误判
            local the_line listen_addr
            the_line=$(grep ""port"[[:space:]]*:[[:space:]]*${port}[^0-9]" "$f" 2>/dev/null | head -1)
            listen_addr=$(echo "$the_line" | grep -oE '"listen"[[:space:]]*:[[:space:]]*"[^"]*"' \
                | grep -oE '"[0-9a-f.:]*"$' | tr -d '"')
            # 若明确绑定在 127.x 或 ::1，跳过
            if [[ -n "$listen_addr" ]]; then
                [[ "$listen_addr" == 127.* || "$listen_addr" == "::1" ]] && continue
            fi
            OPEN_PORTS+=("$port")
        done < <(grep -oE '"port"\s*:\s*[0-9]+' "$f" 2>/dev/null             | grep -oE '[0-9]+' | sort -un)
    done
}

# ── 应用单条跳跃规则（幂等）─────────────────────────────────
apply_hop() {
    local s=$1 e=$2 t=$3
    # 删除同范围旧规则
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep "dpts:${s}:${e}" | awk '{print $1}' | sort -rn)
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
    iptables -P INPUT   ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables -F            2>/dev/null || true
    iptables -X            2>/dev/null || true
    iptables -t nat    -F  2>/dev/null || true
    iptables -t nat    -X  2>/dev/null || true
    iptables -t mangle -F  2>/dev/null || true
}

# ── 应用防火墙规则 ───────────────────────────────────────────
apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        echo
        info "[预览] 开放端口 : ${OPEN_PORTS[*]:-无}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "[预览] 端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
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

    # SSH 防暴力破解（60 秒内 6 次失败封锁）
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

    # FORWARD 放行（NAT 端口跳跃必需）
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT

    # 端口跳跃规则（自动应用）
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ -n "$HOP_S" && -n "$HOP_E" && -n "$HOP_T" ]] || continue
        apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
        ok "端口跳跃已应用: ${HOP_S}-${HOP_E} → ${HOP_T}"
    done

    # 默认丢弃（限速日志）
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

    echo -e "${G}▸ 开放端口 (iptables):${W}"
    iptables -L INPUT -n 2>/dev/null \
        | grep ACCEPT \
        | grep -oE 'dpts?:[0-9:]+' \
        | sort -u \
        | sed 's/dpts\?:/  • /' \
        || echo "  无"

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
        proc=$(ss -tulnp 2>/dev/null \
            | grep -vE '(127\.|::1)' \
            | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"')
        printf "  • %-6s %s\n" "$p" "${proc:-(未知)}"
    done
    hr
}

# ── 重置防火墙 ───────────────────────────────────────────────
reset_fw() {
    echo -e "${R}⚠ 清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }
    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
    iptables -F; iptables -X
    iptables -t nat -F; iptables -t nat -X
    iptables -t mangle -F
    save_rules
    ok "防火墙已重置为全部放行"
}

# ── 手动添加跳跃规则 ─────────────────────────────────────────
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加端口跳跃规则${W}"; hr
    read -rp "端口范围（如 20000-50000）: " hop_range
    read -rp "目标端口（代理实际监听端口）: " target_port
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

# ── 显示汇总 ─────────────────────────────────────────────────
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

    # ① 先检测跳跃规则（端口过滤依赖此步）
    detect_existing_hop_rules
    detect_hysteria_hop

    # ② 再扫描端口（跳跃范围内 + localhost + 系统进程 自动过滤）
    detect_listening_ports
    detect_config_ports

    add_port 80
    add_port 443

    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un) || true
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
