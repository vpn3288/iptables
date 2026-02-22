#!/bin/bash
set -e

# ======================================================
# 🚀 最终版本 1.0 - 全功能代理端口防火墙管理脚本
# ======================================================

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="1.0.0-Ultimate"
SCRIPT_NAME="全功能代理端口防火墙 (最终版)"

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
NAT_RULES=() # 格式: "16820:16999->16801"
OPENED_PORTS=0

# 默认永久开放端口
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心进程
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity" "hiddify"
    "x-ui" "3x-ui" "v2-ui" "nginx" "caddy"
)

# 代理配置文件扫描路径
PROXY_CONFIG_FILES=(
    "/etc/v2ray-agent/hysteria/conf/hysteria.yaml"
    "/etc/v2ray-agent/xray/conf/10_ipv4_inbounds.json"
    "/etc/fscarmen/hysteria/config.yaml"
    "/etc/hysteria/config.yaml"
    "/etc/hysteria/config.json"
    "/etc/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    "/etc/x-ui/config.json"
    "/usr/local/x-ui/bin/config.json"
)

# 内部服务端口与黑名单
INTERNAL_SERVICE_PORTS=(8181 10085 10086 9090 62789 54321)
BLACKLIST_PORTS=(22 23 25 53 111 135 139 445 3306 6379)

# --- 基础工具函数 (保留原始风格) ---
debug_log() { if [ "$DEBUG_MODE" = true ]; then echo -e "${BLUE}[调试] $1${RESET}"; fi; }
error_exit() { echo -e "${RED}❌ $1${RESET}"; exit 1; }
warning() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
success() { echo -e "${GREEN}✅ $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }

format_range() { echo "$1" | tr '-' ':'; }

# --- 核心扫描逻辑 ---

detect_ssh_port() {
    local ssh_p=$(ss -tlnp | grep -w 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    SSH_PORT=${ssh_p:-22}
    info "检测到 SSH 端口: $SSH_PORT"
}

auto_detect_config_rules() {
    info "正在扫描配置文件以识别【端口跳跃】规则..."
    for config in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config" ]; then
            debug_log "正在解析: $config"
            # 识别 YAML (Hysteria2)
            local hop=$(grep -E '^[[:space:]]*(hop|ports):' "$config" | grep -oE '[0-9]+[-:][0-9]+' | head -1 || true)
            if [ -n "$hop" ]; then
                local target=$(grep -E '^[[:space:]]*listen:' "$config" | grep -oE '[0-9]+' | tail -1 || true)
                if [ -n "$target" ]; then
                    local fmt_hop=$(format_range "$hop")
                    NAT_RULES+=("${fmt_hop}->${target}")
                    success "已自动抓取跳跃: $fmt_hop -> $target (来源: $(basename $config))"
                fi
            fi
            # 识别 JSON (Sing-box)
            if [[ "$config" == *.json ]] && command -v jq >/dev/null 2>&1; then
                local j_hop=$(jq -r '.. | select(type == "string" and (contains("-") or contains(":"))) | strings' "$config" 2>/dev/null | grep -E '^[0-9]+[-:][0-9]+$' | head -1 || true)
                if [ -n "$j_hop" ]; then
                    local j_target=$(jq -r '.. | .listen_port? // .port? | select(type == "number")' "$config" | head -1 || true)
                    if [ -n "$j_target" ]; then
                        local fmt_j=$(format_range "$j_hop")
                        NAT_RULES+=("${fmt_j}->${j_target}")
                        success "已自动抓取 JSON 跳跃: $fmt_j -> $j_target"
                    fi
                fi
            fi
        fi
    done
}

detect_active_ports() {
    info "扫描系统中正在监听的代理端口..."
    local p_pattern=$(IFS="|"; echo "${PROXY_CORE_PROCESSES[*]}")
    # 增强扫描：既看进程名，也看活跃监听
    local active_ports=$(ss -tulnp | grep -iE "($p_pattern)" | awk '{print $5}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | sort -nu)
    
    for p in $active_ports; do
        if [ "$p" != "$SSH_PORT" ]; then
            local is_safe=true
            for b in "${BLACKLIST_PORTS[@]}" "${INTERNAL_SERVICE_PORTS[@]}"; do [[ "$p" == "$b" ]] && is_safe=false; done
            [[ "$is_safe" == "true" ]] && DETECTED_PORTS+=("$p")
        fi
    done
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    DETECTED_PORTS=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
}

add_manual_range() {
    echo -e "${CYAN}🔧 手动配置端口跳跃规则${RESET}"
    read -p "请输入对外开放范围 (如 16820-16999): " m_range
    if [[ "$m_range" =~ ^[0-9]+[-:][0-9]+$ ]]; then
        read -p "请输入本地监听端口 (如 16801): " m_target
        if [[ "$m_target" =~ ^[0-9]+$ ]]; then
            local fmt=$(format_range "$m_range")
            NAT_RULES+=("${fmt}->${m_target}")
            success "已手动添加规则: $fmt -> $m_target"
        else echo -e "${RED}端口格式错误${RESET}"; fi
    else echo -e "${RED}范围格式错误${RESET}"; fi
}

# --- 防火墙构建模块 (解决 4.0 的 Bug) ---

apply_iptables_rules() {
    info "应用 Stealth 安全策略与 NAT 转发..."
    if [ "$DRY_RUN" = true ]; then info "[预览模式] 未执行实际修改"; return 0; fi

    # 1. 开启内核转发支持 (NAT 核心)
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

    # 2. 彻底重置 (幂等性保障)
    iptables -P INPUT ACCEPT
    iptables -F && iptables -X
    iptables -t nat -F && iptables -t nat -X

    # 3. 基础 Stealth 放行
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

    # 4. SSH 保护
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 5. 放行离散端口
    for p in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
        iptables -A INPUT -p udp --dport "$p" -j ACCEPT
    done

    # 6. 配置端口跳跃 (NAT + INPUT)
    
    for rule in "${NAT_RULES[@]}"; do
        local range="${rule%->*}"
        local target="${rule#*->}"
        
        # 修正：DNAT 转发语法 (解决 to::16801 偏移)
        iptables -t nat -A PREROUTING -p udp --dport "$range" -j DNAT --to-destination ":$target"
        iptables -t nat -A PREROUTING -p tcp --dport "$range" -j DNAT --to-destination ":$target"
        
        # 修正：必须在 INPUT 链同步放行该范围
        iptables -A INPUT -p udp --dport "$range" -j ACCEPT
        iptables -A INPUT -p tcp --dport "$range" -j ACCEPT
    done

    # 7. 黑洞策略
    iptables -P INPUT DROP
    iptables -P FORWARD DROP

    # 保存
    if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1
    elif [ -d "/etc/iptables" ]; then iptables-save > /etc/iptables/rules.v4; fi
    success "防火墙规则已应用并永久保存。"
}

show_firewall_status() {
    echo -e "\n${BLUE}========== 🛡️ 当前防火墙运行状态 ==========${RESET}"
    
    # 离散端口
    echo -en "${GREEN}● 已放行离散端口: ${RESET}"
    local p_list=$(iptables -L INPUT -n | grep ACCEPT | grep -E 'dpt:[0-9]+' | awk -F'dpt:' '{print $2}' | sort -nu | tr '\n' ' ')
    echo -e "${p_list:-'无'}"

    # NAT 映射
    echo -e "${GREEN}● 端口跳跃 (NAT) 映射:${RESET}"
    local nat_list=$(iptables -t nat -L PREROUTING -n --line-numbers | grep DNAT | awk '{print "  范围:", $8, " -> 目标端口:", $NF}' | sed 's/dpts://g; s/to://g; s/://g')
    if [ -n "$nat_list" ]; then echo -e "$nat_list" | sort -u
    else echo -e "  暂无 NAT 转发规则"; fi

    echo -e "${BLUE}==========================================${RESET}"
}

# --- 主入口 (保留 4.0 全部参数) ---

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug) DEBUG_MODE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --status) show_firewall_status; exit 0 ;;
            --reset) 
                iptables -P INPUT ACCEPT && iptables -F && iptables -t nat -F
                success "防火墙已完全重置"; exit 0 ;;
            --add-range) add_manual_range; apply_iptables_rules; exit 0 ;;
            -h|--help) show_help; exit 0 ;;
            *) shift ;;
        esac
    done

    echo -e "\n${YELLOW}== 🛡️ ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
    
    detect_ssh_port
    auto_detect_config_rules
    detect_active_ports

    # 交互确认
    if [ ${#NAT_RULES[@]} -eq 0 ]; then
        read -p "未发现自动跳跃规则，是否手动配置？[y/N]: " res
        [[ "$res" =~ ^[Yy]$ ]] && add_manual_range
    else
        read -p "是否需要额外手动添加跳跃规则？[y/N]: " res
        [[ "$res" =~ ^[Yy]$ ]] && add_manual_range
    fi

    apply_iptables_rules
    show_firewall_status
    echo -e "\n${GREEN}🎉 配置完成！服务器已处于隐蔽防御状态。${RESET}"
}

show_help() {
    echo -e "用法: bash $0 [选项]"
    echo -e "选项:"
    echo -e "  --status    查看实时规则"
    echo -e "  --reset     一键全开"
    echo -e "  --dry-run   模拟运行"
    echo -e "  --debug     调试日志"
}

main "$@"
