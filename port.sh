#!/bin/bash
# ============================================================
# 代理节点防火墙自动管理脚本 v3.0
# 支持: Hiddify / 3X-UI / X-UI / Sing-box / Xray / V2Ray
#       fscarmen / v2ray-agent / Hysteria2 端口跳跃
# 使用: bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh)
# ============================================================
set -euo pipefail

# ─── 颜色 ───────────────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

# ─── 权限检查 ────────────────────────────────────────────────
[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

# ─── 全局变量 ────────────────────────────────────────────────
SSH_PORT=""
OPEN_PORTS=()          # 最终需要开放的单端口列表
HOP_RULES=()           # 端口跳跃规则: "start:end->target_port"
DRY_RUN=false
VERSION="3.0"

# ─── 帮助 ────────────────────────────────────────────────────
usage() {
cat <<EOF
代理节点防火墙管理脚本 v${VERSION}

用法: bash port.sh [选项]

  (无参数)     自动检测并配置防火墙
  --dry-run    预览模式，不实际修改
  --status     显示当前防火墙状态
  --reset      重置防火墙（全部放行）
  --add-hop    手动添加端口跳跃规则
  --help       显示帮助
EOF
exit 0
}

# ─── 参数解析 ────────────────────────────────────────────────
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --dry-run)  DRY_RUN=true ;;
            --status)   show_status; exit 0 ;;
            --reset)    reset_fw; exit 0 ;;
            --add-hop)  add_hop_interactive; exit 0 ;;
            --help|-h)  usage ;;
            *) err "未知参数: $arg" ;;
        esac
    done
}

# ─── 安装依赖 ────────────────────────────────────────────────
install_deps() {
    local pkgs=()
    command -v iptables   &>/dev/null || pkgs+=(iptables)
    command -v ip6tables  &>/dev/null || pkgs+=(ip6tables)
    command -v ss         &>/dev/null || pkgs+=(iproute2)
    command -v jq         &>/dev/null || pkgs+=(jq)
    command -v curl       &>/dev/null || pkgs+=(curl)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq "${pkgs[@]}" 2>/dev/null
        elif command -v yum &>/dev/null; then
            yum install -y -q "${pkgs[@]}" 2>/dev/null
        fi
    fi

    # 启用 IP 转发（端口跳跃必需）
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null
    grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null \
        || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

    # 隐蔽性优化：关闭不必要的内核响应
    sysctl -w net.ipv4.conf.all.send_redirects=0     &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0   &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true
    sysctl -w net.ipv4.tcp_timestamps=0               &>/dev/null || true  # 隐藏系统时间特征
}

# ─── 检测 SSH 端口 ───────────────────────────────────────────
detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null | awk '/sshd/{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ─── 端口黑名单（危险/内部端口不开放）───────────────────────
is_dangerous() {
    local p=$1
    # 系统危险端口
    local danger=(23 25 53 69 111 135 137 138 139 445 514 631
                  1433 1521 3306 5432 6379 27017 3389 5900 5901
                  110 143 465 587 993 995)
    for d in "${danger[@]}"; do [[ "$p" == "$d" ]] && return 0; done
    # 内部管理端口
    local internal=(8181 9090 3000 3001 8000 8001 54321 62789
                    10085 10086 10080 10081 10082 10083 10084)
    for i in "${internal[@]}"; do [[ "$p" == "$i" ]] && return 0; done
    # SSH 端口另外处理
    [[ "$p" == "$SSH_PORT" ]] && return 0
    return 1
}

# ─── 检测已监听端口 ──────────────────────────────────────────
detect_listening_ports() {
    info "扫描监听端口..."
    local raw_ports=()

    # 从 ss 获取所有监听端口
    while read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] && raw_ports+=("$port")
    done < <(ss -tlnp 2>/dev/null | awk 'NR>1{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' | sort -un)

    # UDP 端口（Hysteria2/QUIC 等）
    while read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] && raw_ports+=("$port")
    done < <(ss -ulnp 2>/dev/null | awk 'NR>1{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' | sort -un)

    # 去重过滤
    local seen=()
    for p in $(echo "${raw_ports[@]}" | tr ' ' '\n' | sort -un); do
        is_dangerous "$p" && continue
        [[ " ${seen[*]} " =~ " $p " ]] && continue
        seen+=("$p")
        OPEN_PORTS+=("$p")
    done
}

# ─── 解析配置文件中的端口 ────────────────────────────────────
detect_config_ports() {
    local configs=(
        /etc/x-ui/config.json
        /opt/3x-ui/bin/config.json
        /usr/local/x-ui/bin/config.json
        /usr/local/etc/xray/config.json
        /etc/xray/config.json
        /usr/local/etc/v2ray/config.json
        /etc/v2ray/config.json
        /etc/sing-box/config.json
        /opt/sing-box/config.json
        /usr/local/etc/sing-box/config.json
        /etc/hysteria/config.json
        /etc/hysteria2/config.json
        /etc/tuic/config.json
        /etc/trojan/config.json
        /opt/hiddify-manager/.env
        /opt/hiddify-manager/hiddify-panel/config.py
    )

    for f in "${configs[@]}"; do
        [[ -f "$f" ]] || continue
        # 提取 "port": 数字 或 :端口 格式
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            [[ "$port" -lt 1 || "$port" -gt 65535 ]] && continue
            is_dangerous "$port" && continue
            [[ " ${OPEN_PORTS[*]} " =~ " $port " ]] && continue
            OPEN_PORTS+=("$port")
        done < <(grep -oE '"port"\s*:\s*[0-9]+|:[0-9]{2,5}[^0-9]' "$f" 2>/dev/null \
                 | grep -oE '[0-9]+' | sort -un)
    done
}

# ─── 检测 Hysteria2 端口跳跃配置 ─────────────────────────────
detect_hysteria2_hop() {
    local hy2_configs=(
        /etc/hysteria/config.json
        /etc/hysteria2/config.json
        /etc/hysteria/config.yaml
        /etc/hysteria2/config.yaml
        /usr/local/etc/hysteria/config.json
        /usr/local/etc/hysteria/config.yaml
    )

    for f in "${hy2_configs[@]}"; do
        [[ -f "$f" ]] || continue

        local listen_port=""
        local hop_range=""

        if [[ "$f" == *.json ]]; then
            # JSON 格式
            listen_port=$(grep -oE '"listen"\s*:\s*"[^"]*"' "$f" 2>/dev/null \
                | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
            hop_range=$(grep -oE '"portHopping"\s*:\s*"[^"]*"' "$f" 2>/dev/null \
                | grep -oE '"[0-9]+-[0-9]+"' | tr -d '"' | head -1)
            [[ -z "$hop_range" ]] && hop_range=$(grep -oE '"portRange"\s*:\s*"[^"]*"' "$f" 2>/dev/null \
                | grep -oE '[0-9]+-[0-9]+' | head -1)
        else
            # YAML 格式
            listen_port=$(grep -E '^\s*listen:' "$f" 2>/dev/null \
                | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
            hop_range=$(grep -E '^\s*portHopping:|^\s*portRange:' "$f" 2>/dev/null \
                | grep -oE '[0-9]+-[0-9]+' | head -1)
        fi

        if [[ -n "$listen_port" && -n "$hop_range" ]]; then
            local rule="${hop_range}->${listen_port}"
            [[ " ${HOP_RULES[*]} " =~ " $rule " ]] || HOP_RULES+=("$rule")
            ok "Hysteria2 端口跳跃: $hop_range → $listen_port"
        elif [[ -n "$listen_port" ]]; then
            # 无显式跳跃配置，询问是否添加
            warn "Hysteria2 端口 $listen_port 无跳跃配置"
        fi
    done

    # 检测 hy2 进程监听端口，尝试从进程参数推断
    local hy2_pid
    hy2_pid=$(pgrep -f 'hysteria' 2>/dev/null | head -1 || true)
    if [[ -n "$hy2_pid" ]]; then
        local hy2_port
        hy2_port=$(ss -ulnp 2>/dev/null | grep "pid=$hy2_pid" \
            | awk '{match($4,/:([0-9]+)$/,a); print a[1]}' | head -1)
        if [[ -n "$hy2_port" ]]; then
            [[ " ${OPEN_PORTS[*]} " =~ " $hy2_port " ]] || OPEN_PORTS+=("$hy2_port")
        fi
    fi
}

# ─── 从进程检测相关端口 ──────────────────────────────────────
detect_process_ports() {
    local procs=(xray v2ray sing-box singbox hysteria hysteria2
                 tuic trojan trojan-go brook gost naive clash mihomo
                 caddy nginx haproxy)

    for proc in "${procs[@]}"; do
        local pid
        pid=$(pgrep -f "$proc" 2>/dev/null | head -1 || true)
        [[ -z "$pid" ]] && continue

        # 通过 ss 获取该进程监听的端口
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            is_dangerous "$port" && continue
            [[ " ${OPEN_PORTS[*]} " =~ " $port " ]] && continue
            OPEN_PORTS+=("$port")
        done < <(ss -tlunp 2>/dev/null | grep "pid=$pid" \
            | grep -oE ':[0-9]+\s' | grep -oE '[0-9]+' | sort -un)
    done
}

# ─── 检测现有 NAT 跳跃规则（避免重复添加）───────────────────
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" =~ DNAT ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        if [[ -n "$range" && -n "$target" ]]; then
            local rule="${range}->${target}"
            [[ " ${HOP_RULES[*]} " =~ " $rule " ]] || HOP_RULES+=("$rule")
        fi
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null)
}

# ─── 交互式添加端口跳跃 ──────────────────────────────────────
add_hop_interactive() {
    detect_ssh
    hr
    echo -e "${C}端口跳跃（Port Hopping）配置向导${W}"
    echo -e "适用于 Hysteria2 / 任意需要多端口入口的代理协议"
    hr
    read -rp "请输入端口范围（如 20000-50000）: " hop_range
    read -rp "请输入目标端口（代理服务实际监听端口）: " target_port

    if [[ ! "$hop_range" =~ ^[0-9]+-[0-9]+$ || ! "$target_port" =~ ^[0-9]+$ ]]; then
        err "输入格式错误"
    fi

    local start_p end_p
    start_p=$(echo "$hop_range" | cut -d- -f1)
    end_p=$(echo "$hop_range"   | cut -d- -f2)

    [[ "$start_p" -ge "$end_p" ]] && err "起始端口需小于结束端口"
    [[ "$target_port" -lt 1 || "$target_port" -gt 65535 ]] && err "目标端口无效"

    info "添加端口跳跃: $hop_range → $target_port"
    apply_single_hop "$start_p" "$end_p" "$target_port"
    ok "端口跳跃规则添加完成"
    save_rules
}

# ─── 应用单条跳跃规则 ────────────────────────────────────────
apply_single_hop() {
    local s=$1 e=$2 t=$3

    # 先删除相同范围的旧规则（幂等）
    iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | awk "/dpts:${s}:${e}/{print \$1}" | sort -rn \
        | while read -r n; do iptables -t nat -D PREROUTING "$n" 2>/dev/null || true; done

    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" -j DNAT --to-destination ":${t}"

    # 开放该范围的 INPUT
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT
}

# ─── 清理旧规则 ──────────────────────────────────────────────
flush_old_rules() {
    info "清理旧防火墙规则..."
    iptables -P INPUT   ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT  ACCEPT 2>/dev/null || true

    iptables -F         2>/dev/null || true
    iptables -X         2>/dev/null || true
    iptables -t nat -F  2>/dev/null || true
    iptables -t nat -X  2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
}

# ─── 应用防火墙规则 ──────────────────────────────────────────
apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        info "[预览] 将开放端口: ${OPEN_PORTS[*]:-无}"
        info "[预览] 端口跳跃规则: ${HOP_RULES[*]:-无}"
        return 0
    fi

    flush_old_rules

    # 基础规则
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP 限速（隐蔽性：不完全屏蔽，防止路由探测异常暴露）
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # SSH 防暴力破解
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH --update --seconds 60 --hitcount 5 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 开放检测到的代理端口
    for port in "${OPEN_PORTS[@]}"; do
        # 幂等检查
        iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null \
            || iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null \
            || iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done

    # 开放 FORWARD（NAT 转发必需）
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT

    # 端口跳跃规则（格式: "16820-16999->16801"）
    for rule in "${HOP_RULES[@]}"; do
        # 用 awk 安全解析，避免 bash 特殊字符问题
        local start_p end_p target
        start_p=$(echo "$rule" | awk -F'[-]' '{print $1}')
        end_p=$(echo "$rule"   | awk -F'[-]' '{print $2}' | awk -F'->' '{print $1}')
        target=$(echo "$rule"  | awk -F'->' '{print $2}')
        [[ -n "$start_p" && -n "$end_p" && -n "$target" ]] || continue
        apply_single_hop "$start_p" "$end_p" "$target"
    done

    # 默认丢弃（限速日志，防止日志洪泛）
    iptables -A INPUT -m limit --limit 5/min \
        -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP
}

# ─── 保存规则 ────────────────────────────────────────────────
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null
    elif [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        # 创建开机自动恢复服务
        if [[ ! -f /etc/systemd/system/iptables-restore.service ]]; then
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
            systemctl daemon-reload   &>/dev/null || true
            systemctl enable iptables-restore.service &>/dev/null || true
        fi
    elif [[ -d /etc/sysconfig ]]; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        systemctl enable iptables &>/dev/null || true
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    ok "规则已保存，重启后自动生效"
}

# ─── 显示状态 ────────────────────────────────────────────────
show_status() {
    hr
    echo -e "${C}当前防火墙状态${W}"
    hr
    echo -e "${G}▸ 开放端口:${W}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT \
        | grep -oE 'dpt[s]?:[0-9:]+' | sed 's/dpts\?:/  • /' || echo "  无"

    echo -e "\n${G}▸ 端口跳跃 (NAT PREROUTING):${W}"
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep DNAT \
        | awk '{
            range=""; target=""
            for(i=1;i<=NF;i++){
                if($i~/dpts:/) range=$i
                if($i~/to:/)   target=$i
            }
            if(range && target) printf "  • %s → %s\n", range, target
        }' || echo "  无"

    echo -e "\n${G}▸ 进程监听端口:${W}"
    ss -tlunp 2>/dev/null | awk 'NR>1{
        match($4,/:([0-9]+)$/,a)
        if(a[1]) printf "  • %s %s\n", $1, $4
    }' | sort -u | head -30
    hr
}

# ─── 重置防火墙 ──────────────────────────────────────────────
reset_fw() {
    echo -e "${R}⚠ 将清除所有 iptables 规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

    iptables -P INPUT   ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT  ACCEPT
    iptables -F; iptables -X
    iptables -t nat -F; iptables -t nat -X
    iptables -t mangle -F
    save_rules
    ok "防火墙已重置"
}

# ─── 显示最终汇总 ────────────────────────────────────────────
show_summary() {
    hr
    echo -e "${G}🎉 防火墙配置完成！${W}"
    hr
    echo -e "${C}SSH 端口   :${W} $SSH_PORT（已保护，防暴力破解）"
    echo -e "${C}开放端口   :${W} ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃   :${W}"
        for r in "${HOP_RULES[@]}"; do
            local s e t
            s=$(echo "$r" | awk -F'[-]' '{print $1}')
            e=$(echo "$r" | awk -F'[-]' '{print $2}' | awk -F'->' '{print $1}')
            t=$(echo "$r" | awk -F'->' '{print $2}')
            echo -e "  ${G}•${W} ${s}-${e} → ${t}"
        done
    fi
    hr
    echo -e "${Y}管理命令:${W}"
    echo "  查看状态  : bash port.sh --status"
    echo "  添加跳跃  : bash port.sh --add-hop"
    echo "  重置防火墙: bash port.sh --reset"
    echo "  查看规则  : iptables -L -n -v"
    echo "  查看NAT   : iptables -t nat -L -n -v"
    hr
}

# ─── 主流程 ──────────────────────────────────────────────────
main() {
    trap 'echo -e "\n${R}中断${W}"; exit 130' INT TERM

    echo -e "${B}══════════════════════════════════════════${W}"
    echo -e "${G}   代理节点防火墙管理脚本 v${VERSION}${W}"
    echo -e "${B}══════════════════════════════════════════${W}"

    parse_args "$@"

    install_deps
    detect_ssh
    detect_existing_hop_rules
    detect_listening_ports
    detect_config_ports
    detect_process_ports
    detect_hysteria2_hop

    # 确保默认端口在列表中
    for p in 80 443; do
        [[ " ${OPEN_PORTS[*]} " =~ " $p " ]] || OPEN_PORTS+=("$p")
    done

    # 去重排序
    OPEN_PORTS=($(echo "${OPEN_PORTS[@]}" | tr ' ' '\n' | sort -un))

    info "检测到需要开放的端口: ${OPEN_PORTS[*]}"
    [[ ${#HOP_RULES[@]} -gt 0 ]] && info "端口跳跃规则: ${HOP_RULES[*]}"

    # 交互确认（非预览模式）
    if [[ "$DRY_RUN" == false ]]; then
        hr
        echo -e "${Y}是否手动添加端口跳跃规则？[y/N]${W}"
        read -r ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            read -rp "端口范围（如 20000-50000）: " hop_range
            read -rp "目标端口: " target_port
            if [[ "$hop_range" =~ ^[0-9]+-[0-9]+$ && "$target_port" =~ ^[0-9]+$ ]]; then
                HOP_RULES+=("${hop_range}->${target_port}")
            else
                warn "格式错误，跳过"
            fi
        fi
    fi

    apply_rules
    save_rules
    show_summary
}

main "$@"
