#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="4.0.0-Enhanced"
SCRIPT_NAME="全功能代理端口防火墙管理脚本 (隐蔽强化版)"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}适配: Hiddify, X-UI, Sing-box, fscarmen, v2ray-agent, Hysteria2${RESET}"
echo -e "${GREEN}🔧 极致安全、防扫描隐蔽、完美端口跳跃、绝对幂等防出错${RESET}"

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 需要 root 权限运行此脚本${RESET}"
    exit 1
fi

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
PORT_RANGES=()
NAT_RULES=()
OPENED_PORTS=0

# 默认永久开放端口
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心与面板进程
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    "trojan" "trojan-go" "trojan-plus"
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
)
WEB_PANEL_PROCESSES=("nginx" "caddy" "apache2" "httpd" "haproxy" "envoy")

# 代理配置文件 (扩充了 fscarmen 和 v2ray-agent 的路径)
PROXY_CONFIG_FILES=(
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/etc/x-ui/config.json"
    "/opt/3x-ui/bin/config.json"
    "/usr/local/x-ui/bin/config.json"
    "/etc/v2ray-agent/xray/conf/10_ipv4_inbounds.json"
    "/etc/v2ray-agent/hysteria/conf/hysteria.yaml"
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    "/etc/hysteria/config.yaml"
    "/etc/hysteria/config.json"
    "/etc/tuic/config.json"
    "/etc/trojan/config.json"
)

# 内部服务端口（不应暴露）
INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 3001 8000 8001
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    54321 62789 9000 9001 9002 8090 8091 8092 8093 8094 8095
)

# 危险端口黑名单
BLACKLIST_PORTS=(
    22 23 25 53 69 111 135 137 138 139 445 514 631
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902
    110 143 465 587 993 995
)

# --- 辅助与基础函数 (保持你原有的优雅设计) ---
debug_log() { if [ "$DEBUG_MODE" = true ]; then echo -e "${BLUE}[调试] $1${RESET}"; fi; }
error_exit() { echo -e "${RED}❌ $1${RESET}"; exit 1; }
warning() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
success() { echo -e "${GREEN}✅ $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }

split_nat_rule() {
    local rule="$1" delimiter="$2" field="$3"
    if [ "$delimiter" = "->" ]; then
        if [ "$field" = "1" ]; then echo "${rule%->*}"
        elif [ "$field" = "2" ]; then echo "${rule#*->}"
        fi
    else
        echo "$rule" | cut -d"$delimiter" -f"$field"
    fi
}

show_help() {
    cat << 'EOF'
精确代理端口防火墙管理脚本 v4.0.0 (隐蔽强化版)

用法: bash script.sh [选项]

选项:
    --debug           显示详细调试信息
    --dry-run         预览模式，不实际修改防火墙
    --add-range       交互式配置 Hysteria2 等端口转发(跳跃)
    --reset           重置防火墙到默认全放行状态
    --status          显示当前防火墙状态与 NAT 映射
    --help, -h        显示此帮助信息
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug) DEBUG_MODE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --add-range) add_port_range_interactive; exit 0 ;;
            --reset) reset_firewall; exit 0 ;;
            --status) show_firewall_status; exit 0 ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        esac
    done
}

check_system() {
    info "检查系统环境..."
    local tools=("iptables" "ss" "jq" "lsof")
    local missing_tools=()
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then missing_tools+=("$tool"); fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        info "正在安装缺失的依赖: ${missing_tools[*]}"
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y iptables iptables-persistent iproute2 jq lsof >/dev/null 2>&1
            elif command -v yum >/dev/null 2>&1; then
                yum install -y iptables iptables-services iproute jq lsof >/dev/null 2>&1
            fi
        fi
    fi
    success "系统环境检查完成"
}

detect_ssh_port() {
    local ssh_port=$(ss -tlnp 2>/dev/null | grep -w 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    SSH_PORT=${ssh_port:-22}
    info "检测到 SSH 端口: $SSH_PORT"
}

# --- 核心网络检测模块 ---
detect_proxy_processes() {
    info "检测运行中的代理服务进程..."
    local found=0
    for process in "${PROXY_CORE_PROCESSES[@]}" "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            debug_log "发现进程: $process"
            found=1
        fi
    done
    if [ $found -eq 1 ]; then success "成功检测到代理/面板进程"; else warning "未检测到运行中的代理进程"; fi
}

parse_config_ports() {
    info "从配置文件解析预设端口..."
    local config_ports=()
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            if [[ "$config_file" =~ \.json$ ]] && command -v jq >/dev/null 2>&1; then
                local ports=$(jq -r '.. | .port? | select(type == "number")' "$config_file" 2>/dev/null | sort -nu)
                for port in $ports; do config_ports+=("$port"); done
            elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                for port in $ports; do config_ports+=("$port"); done
            fi
        fi
    done
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
    fi
}

detect_listening_ports() {
    info "通过 ss 命令探测实际动态监听端口..."
    local listening_ports=()
    local process_pattern=$(IFS="|"; echo "${PROXY_CORE_PROCESSES[*]} | ${WEB_PANEL_PROCESSES[*]}")
    
    local ports=$(ss -tulnp 2>/dev/null | grep -iE "($process_pattern)" | awk '{print $5}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | sort -nu)
    for port in $ports; do
        if [ "$port" != "$SSH_PORT" ]; then
            listening_ports+=("$port")
            debug_log "探测到动态监听端口: $port"
        fi
    done
    DETECTED_PORTS+=("${listening_ports[@]}")
}

is_internal_service_port() {
    local port="$1"
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then return 0; fi
    done
    return 1
}

is_port_safe() {
    local port="$1"
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then return 1; fi
    done
    if is_internal_service_port "$port"; then return 1; fi
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then return 1; fi
    return 0
}

filter_and_confirm_ports() {
    info "正在智能过滤危险端口与内部服务..."
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    
    for port in "${all_ports[@]}"; do
        if is_port_safe "$port"; then safe_ports+=("$port"); fi
    done
    
    DETECTED_PORTS=("${safe_ports[@]}")
    success "端口过滤完成，准备开放 ${#DETECTED_PORTS[@]} 个端口。"
    
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 发现你正在配置防火墙，是否需要配置 Hysteria2/代理的【端口跳跃(NAT映射)】？[y/N]${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            add_port_range_interactive
        fi
    fi
}

# --- 端口映射 (NAT) 交互功能 ---
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口跳跃 (Port Hopping) 映射规则${RESET}"
    echo -e "${YELLOW}说明: 允许客户端通过一个极宽的端口范围连接，自动隐藏并转发到代理的真实监听端口。${RESET}"
    
    while true; do
        read -p "请输入要对外开放的跳跃范围 (格式: 20000-50000): " port_range
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            read -p "请输入实际代理监听的目标单端口 (如: 443 或 8443): " target_port
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                success "已添加跳跃规则: $port_range 将隐蔽转发至本地 $target_port"
                
                read -p "是否继续添加其他映射? [y/N]: " response
                if [[ ! "$response" =~ ^[Yy]$ ]]; then break; fi
            else
                echo -e "${RED}目标端口格式错误。${RESET}"
            fi
        else
            echo -e "${RED}范围格式错误。${RESET}"
        fi
    done
}

# --- 核心防火墙构建与应用 (解决Bug，强化隐蔽) ---
cleanup_firewalls() {
    info "清理历史规则，确保幂等性(不重复产生垃圾规则)..."
    if [ "$DRY_RUN" = true ]; then return 0; fi

    # 禁用 UFW / Firewalld 防止干扰
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
        fi
    done

    # 临时将默认策略改为 ACCEPT，防止在清理过程中自己被踢下线
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # 彻底清空所有表和规则
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    success "防火墙规则已彻底清空重置"
}

apply_firewall_rules() {
    info "注入强化版安全与代理放行规则..."
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 规则不会被应用。"
        return 0
    fi

    # 1. 基础回环与已建立连接放行
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 2. 🛡️ 隐蔽性与防御强化 (Stealth)
    # 丢弃无效与畸形数据包 (防扫描器指纹识别)
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    # 防御 SYN 扫描 (屏蔽非SYN包发起的新建连接请求)
    iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    # 防御 XMAS 和 NULL 恶意扫描
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    # 限制 ICMP Ping (既能 Ping 通排错，又防洪水攻击和存活探测)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/sec --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

    # 3. 🛡️ SSH 防爆破保护
    iptables -N SSH_PROTECT 2>/dev/null || true
    iptables -F SSH_PROTECT
    iptables -A SSH_PROTECT -m recent --name ssh_attempts --set
    iptables -A SSH_PROTECT -m recent --name ssh_attempts --update --seconds 60 --hitcount 5 -j DROP
    iptables -A SSH_PROTECT -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j SSH_PROTECT
    # 确保 SSH 绝对放行
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # 4. 放行探测到的所有代理端口 (TCP 和 UDP 双栈支持)
    for port in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done

    # 5. 🐇 应用端口跳跃 (NAT)
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "配置 NAT 端口跳跃转发规则..."
        # 自动获取当前公网网卡名
        local main_if=$(ip route get 8.8.8.8 2>/dev/null | grep dev | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1)
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            # 配置 DNAT (UDP 和 TCP 双端支持，满足 Hysteria2 和其它协议)
            if [ -n "$main_if" ]; then
                iptables -t nat -A PREROUTING -i "$main_if" -p udp --dport "$port_range" -j DNAT --to-destination ":$target_port"
                iptables -t nat -A PREROUTING -i "$main_if" -p tcp --dport "$port_range" -j DNAT --to-destination ":$target_port"
            else
                # 兼容获取不到网卡的情况
                iptables -t nat -A PREROUTING -p udp --dport "$port_range" -j DNAT --to-destination ":$target_port"
                iptables -t nat -A PREROUTING -p tcp --dport "$port_range" -j DNAT --to-destination ":$target_port"
            fi
            
            # 放行跳跃范围入站
            iptables -A INPUT -p udp --dport "$port_range" -j ACCEPT
            iptables -A INPUT -p tcp --dport "$port_range" -j ACCEPT
        done
    fi

    # 6. 封锁缺省入口 (黑洞模式)
    # 所有未被上述规则匹配的请求直接被丢弃，没有任何错误响应，极致隐蔽！
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "高级防护规则与 NAT 映射注入成功"
    save_iptables_rules
}

save_iptables_rules() {
    info "永久保存 iptables 规则..."
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    elif [ -d "/etc/iptables" ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    elif command -v service >/dev/null 2>&1 && [ -d "/etc/sysconfig" ]; then
        service iptables save >/dev/null 2>&1
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    success "规则保存完成，重启不丢失。"
}

# --- 状态展示模块 ---
show_firewall_status() {
    echo -e "${CYAN}🔍 防火墙当前运行状态${RESET}"
    echo -e "${GREEN}🛡️  SSH 防爆破: ${RESET} $(iptables -L INPUT -n 2>/dev/null | grep -q 'SSH_PROTECT' && echo '已开启 ✅' || echo '未开启 ⚠️')"
    echo -e "${GREEN}🚫 隐蔽与防扫描: ${RESET} $(iptables -L INPUT -n 2>/dev/null | grep -q 'INVALID' && echo '已激活 ✅' || echo '未激活 ⚠️')"
    
    echo -e "\n${GREEN}🔓 已放行公网端口:${RESET}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E 'dpt[s]?:[0-9]+' | awk '{print $4, $NF}' | sort -u | while read -r line; do
        echo -e "  • $line"
    done
    
    echo -e "\n${GREEN}🐇 NAT 端口跳跃映射:${RESET}"
    local nat_count=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep -c DNAT || true)
    if [ "$nat_count" -gt 0 ]; then
        iptables -t nat -L PREROUTING -n 2>/dev/null | grep DNAT | awk '{print "  • 外部范围:", $7, "-->", $NF}' | sort -u
    else
        echo -e "  ${YELLOW}暂无跳跃规则${RESET}"
    fi
    echo -e "\n${YELLOW}提示: 若需修改，请直接重新运行此脚本。${RESET}"
}

reset_firewall() {
    echo -e "${YELLOW}🔄 即将重置防火墙为默认开放状态${RESET}"
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t mangle -F
    save_iptables_rules
    success "防火墙已完全重置并开放所有端口"
}

# --- 主入口 ---
main() {
    trap 'echo -e "\n${RED}操作被用户中断${RESET}"; exit 130' INT TERM
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始深度扫描并配置代理防火墙...${RESET}"
    check_system
    detect_ssh_port
    
    detect_proxy_processes
    parse_config_ports
    detect_listening_ports
    
    filter_and_confirm_ports
    cleanup_firewalls
    apply_firewall_rules
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${GREEN}==========================================${RESET}"
        echo -e "🎉 代理端口防火墙配置完成！"
        echo -e "🛡️ 新增特性: 恶意扫描丢弃 (Stealth) / SSH 爆破防御"
        echo -e "✨ 完美解决: 支持多次重复运行，不堆叠产生垃圾规则"
        echo -e "查看状态: bash $0 --status"
        echo -e "${GREEN}==========================================${RESET}"
    fi
}

main "$@"
