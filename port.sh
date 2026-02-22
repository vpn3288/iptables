#!/bin/bash
set -e

# ======================================================
# 🚀 全功能代理端口防火墙管理脚本 v6.0 (终极完善版)
# ======================================================

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="6.0.0-Ultimate"
SCRIPT_NAME="全功能代理端口防火墙"

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
PORT_RANGES=()
NAT_RULES=() # 内部存储格式: "范围->目标" 如 "16820:16999->16801"
OPENED_PORTS=0

# 默认永久开放端口
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心与面板进程
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity"
    "hiddify" "x-ui" "3x-ui" "v2-ui"
    "trojan" "naive" "mihomo"
)
WEB_PANEL_PROCESSES=("nginx" "caddy" "haproxy")

# 代理配置文件路径 (扩充了 fscarmen 和 v2ray-agent 的路径)
PROXY_CONFIG_FILES=(
    "/etc/v2ray-agent/hysteria/conf/hysteria.yaml"
    "/etc/v2ray-agent/xray/conf/10_ipv4_inbounds.json"
    "/etc/fscarmen/hysteria/config.yaml"
    "/etc/hysteria/config.yaml"
    "/etc/hysteria/config.json"
    "/etc/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    "/etc/x-ui/config.json"
    "/opt/hiddify-manager/hiddify-panel/config.py"
)

# 内部服务端口与黑名单
INTERNAL_SERVICE_PORTS=(8181 10085 10086 9090 62789 54321 3000 8000)
BLACKLIST_PORTS=(22 23 25 53 111 135 139 445 3306 6379)

# --- 辅助与基础函数 (保留 4.0 优雅设计) ---
debug_log() { if [ "$DEBUG_MODE" = true ]; then echo -e "${BLUE}[调试] $1${RESET}"; fi; }
error_exit() { echo -e "${RED}❌ $1${RESET}"; exit 1; }
warning() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
success() { echo -e "${GREEN}✅ $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }

split_nat_rule() {
    local rule="$1" delimiter="$2" field="$3"
    if [ "$delimiter" = "->" ]; then
        if [ "$field" = "1" ]; then echo "${rule%->*}"; else echo "${rule#*->}"; fi
    else
        echo "$rule" | cut -d"$delimiter" -f"$field"
    fi
}

# 格式化端口范围：将 100-200 转换为 100:200 以适配 iptables
format_range() {
    echo "$1" | tr '-' ':'
}

show_help() {
    echo -e "${YELLOW}用法: bash $0 [选项]${RESET}"
    echo -e "选项:"
    echo -e "  --debug     显示详细调试信息"
    echo -e "  --dry-run   预览模式，不实际修改防火墙"
    echo -e "  --add-range 手动交互添加端口转发规则"
    echo -e "  --status    查看当前规则统计和映射状态"
    echo -e "  --reset     重置所有规则为 ACCEPT"
}

# --- 核心探测模块 ---

check_system() {
    info "检查系统环境..."
    local tools=("iptables" "ss" "jq" "lsof")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y jq iptables-persistent >/dev/null 2>&1
            elif command -v yum >/dev/null; then yum install -y jq iptables-services >/dev/null 2>&1; fi
        fi
    done
}

detect_ssh_port() {
    local ssh_p=$(ss -tlnp 2>/dev/null | grep -w 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    SSH_PORT=${ssh_p:-22}
    info "检测到 SSH 端口: $SSH_PORT"
}

# [自动识别功能] 自动从配置文件探测端口跳跃规则
auto_detect_nat_rules() {
    info "正在自动检索配置文件中的端口跳跃 (NAT) 规则..."
    for config in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config" ]; then
            debug_log "扫描配置: $config"
            # 匹配 Hysteria2 的 YAML 格式 (hop: 20000-30000)
            local h_range=$(grep -E '^[[:space:]]*(hop|ports):' "$config" | grep -oE '[0-9]+[-:][0-9]+' | head -1)
            if [ -n "$h_range" ]; then
                local h_target=$(grep -E '^[[:space:]]*listen:' "$config" | grep -oE '[0-9]+' | tail -1)
                if [ -n "$h_target" ]; then
                    local fmt_range=$(format_range "$h_range")
                    NAT_RULES+=("${fmt_range}->${h_target}")
                    success "自动识别跳跃: $fmt_range 转发至 $h_target"
                fi
            fi
            # 匹配 Sing-box 的 JSON 格式
            if [[ "$config" == *.json ]] && command -v jq >/dev/null 2>&1; then
                local j_hops=$(jq -r '.. | select(type == "string" and (contains("-") or contains(":"))) | strings' "$config" 2>/dev/null | grep -E '^[0-9]+[-:][0-9]+$' || true)
                for j_h in $j_hops; do
                    local j_t=$(jq -r '.. | .listen_port? // .port? | select(type == "number")' "$config" | head -1)
                    if [ -n "$j_t" ]; then
                        local fmt_j=$(format_range "$j_h")
                        NAT_RULES+=("${fmt_j}->${j_t}")
                        success "自动识别 JSON 跳跃: $fmt_j 转发至 $j_t"
                    fi
                done
            fi
        fi
    done
}

detect_listening_ports() {
    info "通过网络栈探测动态监听端口..."
    local p_pattern=$(IFS="|"; echo "${PROXY_CORE_PROCESSES[*]}|${WEB_PANEL_PROCESSES[*]}")
    local ports=$(ss -tulnp 2>/dev/null | grep -iE "($p_pattern)" | awk '{print $5}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | sort -nu)
    for p in $ports; do
        if [ "$p" != "$SSH_PORT" ]; then DETECTED_PORTS+=("$p"); fi
    done
}

filter_and_confirm() {
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    local unique=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe=()
    for p in "${unique[@]}"; do
        local is_safe=true
        for b in "${BLACKLIST_PORTS[@]}" "${INTERNAL_SERVICE_PORTS[@]}"; do [[ "$p" == "$b" ]] && is_safe=false; done
        [[ "$is_safe" == "true" ]] && safe+=("$p")
    done
    DETECTED_PORTS=("${safe[@]}")
    success "端口探测完成，共 ${#DETECTED_PORTS[@]} 个离散端口。"

    # 如果自动识别没找到，或者用户想手动加
    if [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 未发现自动跳跃规则，是否手动配置 Hysteria2 跳跃范围？[y/N]${RESET}"
        read -r res; if [[ "$res" =~ ^[Yy]$ ]]; then add_port_range_interactive; fi
    else
        echo -e "\n${GREEN}💡 已自动识别到 ${#NAT_RULES[@]} 条跳跃规则。是否需要额外手动添加？[y/N]${RESET}"
        read -r res; if [[ "$res" =~ ^[Yy]$ ]]; then add_port_range_interactive; fi
    fi
}

add_port_range_interactive() {
    while true; do
        read -p "请输入开放范围 (例如 20000-50000): " m_range
        if [[ "$m_range" =~ ^[0-9]+[-:][0-9]+$ ]]; then
            read -p "请输入本地目标端口 (例如 16801): " m_target
            if [[ "$m_target" =~ ^[0-9]+$ ]]; then
                local fmt=$(format_range "$m_range")
                NAT_RULES+=("${fmt}->${m_target}")
                success "记录手动规则: $fmt -> $m_target"
                read -p "继续添加? [y/N]: " cont; [[ ! "$cont" =~ ^[Yy]$ ]] && break
            else echo -e "${RED}目标端口无效${RESET}"; fi
        else echo -e "${RED}范围格式错误 (需为 100-200 或 100:200)${RESET}"; fi
    done
}

# --- 核心防火墙应用 (解决 4.0 的 Bug 并强化隐蔽性) ---

apply_firewall_rules() {
    info "正在注入强化版安全策略..."
    if [ "$DRY_RUN" = true ]; then info "[预览模式] 跳过实际应用"; return 0; fi

    # 1. 重置 (幂等性保障)
    iptables -P INPUT ACCEPT
    iptables -F && iptables -X
    iptables -t nat -F && iptables -t nat -X

    # 2. 隐蔽性优化 (Stealth)
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # 3. SSH 保护 (防爆破)
    iptables -N SSH_PROTECT
    iptables -A SSH_PROTECT -m recent --name ssh_logs --set
    iptables -A SSH_PROTECT -m recent --name ssh_logs --update --seconds 60 --hitcount 5 -j DROP
    iptables -A SSH_PROTECT -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j SSH_PROTECT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 4. 放行探测到的离散端口
    for p in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
        iptables -A INPUT -p udp --dport "$p" -j ACCEPT
    done

    # 5. [核心修复] 应用端口跳跃 (NAT) 
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local main_if=$(ip route get 8.8.8.8 | grep dev | awk '{print $5}' | head -1)
        for rule in "${NAT_RULES[@]}"; do
            local range=$(split_nat_rule "$rule" "->" "1")
            local target=$(split_nat_rule "$rule" "->" "2")
            
            # DNAT 转发 (UDP 为主，TCP 备用)
            iptables -t nat -A PREROUTING -p udp --dport "$range" -j DNAT --to-destination ":$target"
            iptables -t nat -A PREROUTING -p tcp --dport "$range" -j DNAT --to-destination ":$target"
            
            # 必须在 INPUT 链也放行该范围，否则流量会被拦截
            iptables -A INPUT -p udp --dport "$range" -j ACCEPT
            iptables -A INPUT -p tcp --dport "$range" -j ACCEPT
        done
    fi

    # 6. 默认丢弃 (黑洞模式)
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    
    # 7. 保存规则
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    fi
    success "防火墙规则已生效并永久保存。"
}

show_firewall_status() {
    echo -e "${CYAN}🔍 当前防火墙状态摘要:${RESET}"
    echo -e "${GREEN}● 已放行离散端口:${RESET} ${DETECTED_PORTS[*]}"
    echo -e "${GREEN}● 端口跳跃 (NAT) 映射:${RESET}"
    local nats=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep DNAT)
    if [ -n "$nats" ]; then
        echo "$nats" | awk '{print "  • 外部范围:", $7, " -> 目标:", $NF}'
    else
        echo "  暂无活动的 NAT 跳跃规则"
    fi
    echo -e "${GREEN}● 隐蔽性防护:${RESET} 已启用 (INVALID包丢弃/ICMP限制)"
}

# --- 主逻辑 ---
main() {
    parse_args() {
        while [[ $# -gt 0 ]]; do
            case $1 in
                --debug) DEBUG_MODE=true; shift ;;
                --dry-run) DRY_RUN=true; shift ;;
                --status) show_firewall_status; exit 0 ;;
                --reset) 
                    iptables -P INPUT ACCEPT && iptables -F && iptables -t nat -F
                    success "防火墙已完全重置"; exit 0 ;;
                --add-range) add_port_range_interactive; apply_firewall_rules; exit 0 ;;
                -h|--help) show_help; exit 0 ;;
                *) shift ;;
            esac
        done
    }
    parse_args "$@"

    echo -e "\n${YELLOW}== 🛡️ ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
    
    check_system
    detect_ssh_port
    auto_detect_nat_rules
    detect_listening_ports
    
    filter_and_confirm
    apply_firewall_rules
    show_firewall_status
}

main "$@"
