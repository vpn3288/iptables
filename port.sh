# 7. 检测监听端口
    detect_listening_ports#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="2.0.0"
SCRIPT_NAME="精准代理端口防火墙管理脚本（iptables版）"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}专为 Hiddify、3X-UI、X-UI、Sing-box、Xray 等代理面板优化${RESET}"
echo -e "${GREEN}🔧 使用iptables确保最佳兼容性${RESET}"

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 需要 root 权限运行${RESET}"
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

# 默认恒定开放端口（不需要检测）
DEFAULT_OPEN_PORTS=(80 443)

# 精准代理进程识别（基于实际使用场景）
PROXY_CORE_PROCESSES=(
    # 核心代理引擎
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    # 现代协议
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    # 管理面板主进程
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    # Trojan系列
    "trojan" "trojan-go" "trojan-plus"
    # Shadowsocks系列
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    # 其他代理
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
)

# Web面板进程（通常托管管理界面）
WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" "haproxy" "envoy"
)

# 代理配置文件路径（精准定位）
PROXY_CONFIG_FILES=(
    # Hiddify相关
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/log/system/hiddify-panel.log"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/opt/hiddify-manager/.env"
    
    # 3X-UI / X-UI
    "/etc/x-ui/config.json"
    "/opt/3x-ui/bin/config.json"
    "/usr/local/x-ui/bin/config.json"
    
    # Xray/V2Ray
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    
    # Sing-box
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    
    # 其他配置
    "/etc/hysteria/config.json"
    "/etc/tuic/config.json"
    "/etc/trojan/config.json"
)

# Hiddify专用端口识别（基于实际部署）
HIDDIFY_COMMON_PORTS=(
    # 管理面板
    "443" "8443" "9443"
    # 常见代理端口
    "80" "8080" "8880"
    # Hiddify默认端口范围
    "2053" "2083" "2087" "2096"
    "8443" "8880"
)

# 代理协议标准端口（精确识别）
STANDARD_PROXY_PORTS=(
    # HTTP/HTTPS代理
    "80" "443" "8080" "8443" "8880" "8888"
    # SOCKS代理
    "1080" "1085"
    # Shadowsocks常用端口
    "8388" "8389" "9000" "9001"
    # 常见代理端口
    "2080" "2443" "3128" "8964"
    # Trojan端口
    "8443" "9443"
)

# 内部服务端口（不应对外开放）
INTERNAL_SERVICE_PORTS=(
    # 常见内部端口
    8181 10085 10086 9090 3000 3001 8000 8001
    # Sing-box 内部端口范围
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    # X-UI 内部端口
    54321 62789
    # Hiddify 内部端口
    9000 9001 9002
    # 其他管理端口
    8090 8091 8092 8093 8094 8095
)

# 危险端口黑名单（绝不开放）
BLACKLIST_PORTS=(
    # 系统关键端口
    22 23 25 53 69 111 135 137 138 139 445 514 631
    # 数据库端口
    1433 1521 3306 5432 6379 27017
    # 远程管理端口
    3389 5900 5901 5902
    # 邮件服务端口
    110 143 465 587 993 995
    # 内部服务端口（不对外）
    8181 10085 10086
)

# SSH暴力破解保护相关
SSH_ATTEMPTS_FILE="/tmp/ssh_attempts"
SSH_BAN_TIME=3600  # 1小时

# 辅助函数
debug_log() { if [ "$DEBUG_MODE" = true ]; then echo -e "${BLUE}[DEBUG] $1${RESET}"; fi; }
error_exit() { echo -e "${RED}❌ $1${RESET}"; exit 1; }
warning() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
success() { echo -e "${GREEN}✓ $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }

# 字符串分割函数
split_nat_rule() {
    local rule="$1"
    local delimiter="$2"
    local field="$3"
    
    if [ "$delimiter" = "->" ]; then
        if [ "$field" = "1" ]; then
            echo "${rule%->*}"  # 返回->之前的部分
        elif [ "$field" = "2" ]; then
            echo "${rule#*->}"  # 返回->之后的部分
        fi
    else
        echo "$rule" | cut -d"$delimiter" -f"$field"
    fi
}

# 显示帮助
show_help() {
    cat << 'EOF'
精准代理端口防火墙管理脚本 v2.0.0 (iptables版)

专为现代代理面板设计的智能端口管理工具

用法: bash script.sh [选项]

选项:
    --debug           显示详细调试信息
    --dry-run         预演模式，不实际修改防火墙
    --add-range       交互式添加端口跳跃规则
    --reset           重置防火墙到默认状态
    --status          查看当前防火墙状态
    --help, -h        显示此帮助信息

支持的代理面板/软件:
    ✓ Hiddify Manager/Panel
    ✓ 3X-UI / X-UI
    ✓ Xray / V2Ray
    ✓ Sing-box
    ✓ Hysteria / Hysteria2
    ✓ Trojan-Go / Trojan
    ✓ Shadowsocks系列
    ✓ 其他主流代理工具

安全特性:
    ✓ 精准端口识别，避免开放不必要端口
    ✓ 自动过滤内部服务端口
    ✓ 自动过滤危险端口
    ✓ SSH暴力破解保护
    ✓ 基于iptables的稳定防火墙

新版本特性 (v2.0.0):
    ✓ 完全基于iptables，兼容性最佳
    ✓ 支持所有主流Linux发行版
    ✓ 与现有代理安装脚本完全兼容
    ✓ 优化的端口跳跃功能
    ✓ 增强的SSH保护机制

端口跳跃说明:
    端口跳跃允许将一个端口范围的流量转发到单个目标端口，
    例如: 16820-16888 → 16801
    这对于绕过某些网络限制或负载均衡非常有用。

EOF
}

# 参数解析
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

# 检查系统环境
check_system() {
    info "检查系统环境..."
    
    # 检查并安装必要工具
    local tools=("iptables" "ss" "jq")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        info "安装缺失的工具: ${missing_tools[*]}"
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y iptables iproute2 jq netstat-nat
            elif command -v yum >/dev/null 2>&1; then
                yum install -y iptables iproute jq
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y iptables iproute jq
            elif command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm iptables iproute2 jq
            fi
        fi
    fi
    
    # 检查内核模块
    local required_modules=("iptable_nat" "iptable_filter" "ip_conntrack")
    for module in "${required_modules[@]}"; do
        if ! lsmod | grep -q "^$module" && [ "$DRY_RUN" = false ]; then
            modprobe "$module" 2>/dev/null || true
        fi
    done
    
    success "系统环境检查完成"
}

# 检测SSH端口
detect_ssh_port() {
    debug_log "检测SSH端口..."
    
    # 优先从进程监听检测
    local ssh_port=$(ss -tlnp 2>/dev/null | grep -E ':22\b|sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    
    # 从配置文件检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    # 默认SSH端口
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    info "检测到SSH端口: $SSH_PORT"
}

# 检测现有NAT规则和端口跳跃
detect_existing_nat_rules() {
    info "检测现有端口跳跃规则..."
    
    local nat_rules=()
    local unique_rules=()
    
    # 检测iptables NAT规则
    if command -v iptables >/dev/null 2>&1; then
        while IFS= read -r line; do
            if echo "$line" | grep -qE "DNAT.*udp.*dpts:[0-9]+:[0-9]+.*to:[0-9]+"; then
                local port_range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | grep -oE "[0-9]+:[0-9]+" | sed 's/:/-/')
                local target_port=$(echo "$line" | grep -oE "to:[0-9\.]+:[0-9]+" | grep -oE "[0-9]+$")
                if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                    local rule_key="$port_range->$target_port"
                    nat_rules+=("$rule_key")
                    debug_log "发现iptables端口跳跃规则: $port_range -> $target_port"
                fi
            fi
        done <<< "$(iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep DNAT)"
    fi
    
    # 去重NAT规则
    if [ ${#nat_rules[@]} -gt 0 ]; then
        unique_rules=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        NAT_RULES=("${unique_rules[@]}")
        
        # 将目标端口添加到检测端口列表
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ]; then
                DETECTED_PORTS+=("$target_port")
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔄 检测到现有端口跳跃规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        success "检测到 ${#NAT_RULES[@]} 个端口跳跃规则"
    else
        info "未检测到现有端口跳跃规则"
    fi
}

# 智能端口跳跃规则自动生成
auto_generate_port_hopping_suggestions() {
    info "分析端口跳跃规则建议..."
    
    local suggestions=()
    local listening_proxy_ports=()
    
    # 获取代理相关的监听端口
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]]; then
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            local port=$(echo "$address_port" | grep -oE '[0-9]+
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口跳跃规则${RESET}"
    echo -e "${YELLOW}端口跳跃允许将一个端口范围转发到单个目标端口${RESET}"
    echo -e "${YELLOW}例如: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}请输入端口范围 (格式: 起始端口-结束端口，如 16820-16888):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_port="${BASH_REMATCH[1]}"
            local end_port="${BASH_REMATCH[2]}"
            
            if [ "$start_port" -ge "$end_port" ]; then
                error_exit "起始端口必须小于结束端口"
            fi
            
            echo -e "${CYAN}请输入目标端口 (单个端口号):${RESET}"
            read -r target_port
            
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                DETECTED_PORTS+=("$target_port")
                success "添加端口跳跃规则: $port_range -> $target_port"
                
                echo -e "${YELLOW}是否继续添加其他端口跳跃规则? [y/N]${RESET}"
                read -r response
                if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    break
                fi
            else
                echo -e "${RED}无效的目标端口: $target_port${RESET}"
            fi
        else
            echo -e "${RED}无效的端口范围格式: $port_range${RESET}"
        fi
    done
}

# 智能检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found_processes=()
    
    # 检查核心代理进程
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现代理进程: $process"
        fi
    done
    
    # 检查Web面板进程
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现Web面板进程: $process"
        fi
    done
    
    if [ ${#found_processes[@]} -gt 0 ]; then
        success "检测到代理相关进程: ${found_processes[*]}"
        return 0
    else
        warning "未检测到运行中的代理进程"
        return 1
    fi
}

# 检查绑定地址类型
check_bind_address() {
    local address="$1"
    
    # 检查是否是公网监听地址
    if [[ "$address" =~ ^(\*|0\.0\.0\.0|\[::\]|::): ]]; then
        echo "public"
    # 检查是否是本地回环地址
    elif [[ "$address" =~ ^(127\.|::1|\[::1\]): ]]; then
        echo "localhost"
    # 检查是否是内网地址
    elif [[ "$address" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.): ]]; then
        echo "private"
    # 其他情况
    else
        echo "unknown"
    fi
}

# 从配置文件解析端口
parse_config_ports() {
    info "解析配置文件中的端口..."
    
    local config_ports=()
    
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "分析配置文件: $config_file"
            
            # 根据文件类型解析端口
            if [[ "$config_file" =~ \.json$ ]]; then
                # JSON配置文件
                if command -v jq >/dev/null 2>&1; then
                    # 更精确的JSON解析，查找inbounds中的公网监听端口
                    local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析到公网端口: $port"
                        done <<< "$ports"
                    fi
                    
                    # 也检查简单的port字段
                    local simple_ports=$(jq -r '.. | objects | select(has("port")) | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$simple_ports" ]; then
                        while read -r port; do
                            # 只添加不在内部服务端口列表中的端口
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 解析到端口: $port"
                            else
                                debug_log "跳过内部服务端口: $port"
                            fi
                        done <<< "$simple_ports"
                    fi
                else
                    # 简单文本解析
                    local ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 文本解析到端口: $port"
                            fi
                        done <<< "$ports"
                    fi
                fi
            elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                # YAML配置文件
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file YAML解析到端口: $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    # 去重并存储
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从配置文件解析到 ${#unique_ports[@]} 个端口"
    fi
}

# 检测监听端口（改进版）
detect_listening_ports() {
    info "检测当前监听端口..."
    
    local listening_ports=()
    local localhost_ports=()
    
    # 使用ss命令检测
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local protocol=$(echo "$line" | awk '{print tolower($1)}')
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            
            # 提取端口号
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            
            # 提取进程名
            local process="unknown"
            if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
                process="${BASH_REMATCH[1]}"
            fi
            
            # 检查绑定地址类型
            local bind_type=$(check_bind_address "$address_port")
            
            debug_log "检测到监听: $address_port ($protocol, $process, $bind_type)"
            
            # 检查是否是代理相关进程
            if is_proxy_related "$process" && [ -n "$port" ] && [ "$port" != "$SSH_PORT" ]; then
                if [ "$bind_type" = "public" ]; then
                    # 公网监听端口
                    if ! is_internal_service_port "$port"; then
                        listening_ports+=("$port")
                        debug_log "检测到公网代理端口: $port ($protocol, $process)"
                    else
                        debug_log "跳过内部服务端口: $port"
                    fi
                elif [ "$bind_type" = "localhost" ]; then
                    # 本地监听端口（记录但不开放）
                    localhost_ports+=("$port")
                    debug_log "检测到本地代理端口: $port ($protocol, $process) - 不对外开放"
                fi
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    # 显示本地监听端口信息
    if [ ${#localhost_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 检测到内部服务端口 (仅本地监听):${RESET}"
        for port in $(printf '%s\n' "${localhost_ports[@]}" | sort -nu); do
            echo -e "  ${YELLOW}• $port${RESET} - 内部服务，不对外开放"
        done
    fi
    
    # 去重并添加到检测列表
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "检测到 ${#unique_ports[@]} 个公网监听端口"
    fi
}

# 判断是否是代理相关进程
is_proxy_related() {
    local process="$1"
    
    # 精确匹配
    for proxy_proc in "${PROXY_CORE_PROCESSES[@]}" "${WEB_PANEL_PROCESSES[@]}"; do
        if [[ "$process" == *"$proxy_proc"* ]]; then
            return 0
        fi
    done
    
    # 模糊匹配常见代理关键词
    if [[ "$process" =~ (proxy|vpn|tunnel|shadowsocks|trojan|v2ray|xray|clash|hysteria|sing) ]]; then
        return 0
    fi
    
    return 1
}

# 检查是否是内部服务端口
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# 检查是否是标准代理端口
is_standard_proxy_port() {
    local port="$1"
    
    # 检查常用代理端口
    local common_ports=(80 443 1080 1085 8080 8388 8443 8880 8888 9443)
    for common_port in "${common_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    # 检查高端口范围（10000-10999, 30000-39999）- 但排除已知内部端口
    if [ "$port" -ge 30000 ] && [ "$port" -le 39999 ]; then
        return 0
    fi
    if [ "$port" -ge 40000 ] && [ "$port" -le 65000 ] && ! is_internal_service_port "$port"; then
        return 0
    fi
    
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    # 检查是否在黑名单中
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then
            debug_log "端口 $port 在黑名单中"
            return 1
        fi
    done
    
    # 检查是否是内部服务端口
    if is_internal_service_port "$port"; then
        debug_log "端口 $port 是内部服务端口"
        return 1
    fi
    
    # 端口范围检查
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        debug_log "端口 $port 超出有效范围"
        return 1
    fi
    
    # 默认开放端口（80, 443）始终安全
    if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
        debug_log "端口 $port 是默认开放端口"
        return 0
    fi
    
    return 0
}

# 智能端口过滤和确认
filter_and_confirm_ports() {
    info "智能端口分析和确认..."
    
    # 添加默认开放端口（80、443）
    info "添加默认开放端口: ${DEFAULT_OPEN_PORTS[*]}"
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    # 去重所有检测到的端口
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    local suspicious_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
    # 分类端口
    for port in "${all_ports[@]}"; do
        if ! is_port_safe "$port"; then
            if is_internal_service_port "$port"; then
                internal_ports+=("$port")
            else
                unsafe_ports+=("$port")
            fi
        elif is_standard_proxy_port "$port" || [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
            safe_ports+=("$port")
        else
            # 其他端口需要进一步检查
            suspicious_ports+=("$port")
        fi
    done
    
    # 显示检测结果
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 标准代理端口 (推荐开放):${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} - 默认开放端口"
            else
                echo -e "  ${GREEN}✓ $port${RESET} - 常见代理端口"
            fi
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 内部服务端口 (已过滤):${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "  ${YELLOW}- $port${RESET} - 内部服务端口，不对外开放"
        done
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}⚠️  可疑端口 (建议确认):${RESET}"
        for port in "${suspicious_ports[@]}"; do
            echo -e "  ${YELLOW}? $port${RESET} - 不是标准代理端口"
        done
        
        echo -e "\n${YELLOW}这些端口可能不是必需的代理端口，建议确认后再开放${RESET}"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}是否也要开放这些可疑端口? [y/N]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                safe_ports+=("${suspicious_ports[@]}")
                info "用户确认开放可疑端口"
            else
                info "跳过可疑端口"
            fi
        fi
    fi
    
    if [ ${#unsafe_ports[@]} -gt 0 ]; then
        echo -e "\n${RED}❌ 危险端口 (已跳过):${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "  ${RED}✗ $port${RESET} - 系统端口或危险端口"
        done
    fi
    
    # 询问用户是否需要配置端口跳跃
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 是否需要配置端口跳跃功能? [y/N]${RESET}"
        echo -e "${YELLOW}端口跳跃可以将一个端口范围转发到单个目标端口${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            # 首先尝试智能生成建议
            auto_generate_port_hopping_suggestions
            
            # 然后提供手动添加选项
            if [ ${#NAT_RULES[@]} -eq 0 ]; then
                echo -e "\n${CYAN}没有自动生成建议，是否手动配置端口跳跃规则? [y/N]${RESET}"
                read -r manual_response
                if [[ "$manual_response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    add_port_range_interactive
                fi
            else
                echo -e "\n${CYAN}是否还需要手动添加更多端口跳跃规则? [y/N]${RESET}"
                read -r additional_response
                if [[ "$additional_response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    add_port_range_interactive
                fi
            fi
        fi
    elif [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -gt 0 ]; then
        # 如果已有端口跳跃规则，询问是否添加更多
        echo -e "\n${CYAN}🔄 检测到现有端口跳跃规则，是否需要添加更多? [y/N]${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            # 尝试智能补充建议
            auto_generate_port_hopping_suggestions
            
            echo -e "\n${CYAN}是否手动添加端口跳跃规则? [y/N]${RESET}"
            read -r manual_response
            if [[ "$manual_response" =~ ^[Yy]([eE][sS])?$ ]]; then
                add_port_range_interactive
            fi
        fi
    fi
    
    # 用户最终确认
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "没有检测到需要开放的标准代理端口"
        # 至少开放默认端口
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}📋 最终将开放以下端口:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (默认开放)"
            else
                echo -e "  ${CYAN}• $port${RESET}"
            fi
        done
        
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
            for rule in "${NAT_RULES[@]}"; do
                echo -e "  ${CYAN}• $rule${RESET}"
            done
        fi
        
        echo -e "\n${YELLOW}确认开放以上 ${#safe_ports[@]} 个端口"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "以及 ${#NAT_RULES[@]} 个端口跳跃规则"
        fi
        echo -e "? [Y/n]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]?$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    # 更新全局端口列表（去重）
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 将清理现有防火墙"
        return 0
    fi
    
    # 停用其他防火墙服务
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "已停用 $service"
        fi
    done
    
    # 重置UFW（如果存在）
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 备份现有NAT规则到临时文件
    local nat_backup="/tmp/nat_rules_backup.txt"
    iptables-save -t nat > "$nat_backup" 2>/dev/null || true
    
    # 清理filter表规则但保留基本策略
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F INPUT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    
    # 清理自定义链
    iptables -X 2>/dev/null || true
    
    success "防火墙清理完成（保留NAT规则）"
}

# 创建SSH暴力破解保护
setup_ssh_protection() {
    info "设置SSH暴力破解保护..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 将设置SSH保护"
        return 0
    fi
    
    # 创建SSH保护链
    iptables -N SSH_PROTECTION 2>/dev/null || true
    iptables -F SSH_PROTECTION 2>/dev/null || true
    
    # SSH暴力破解保护规则
    # 允许已建立的连接
    iptables -A SSH_PROTECTION -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 限制新SSH连接频率（每分钟最多3次尝试）
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --set
    
    # 接受符合频率限制的SSH连接
    iptables -A SSH_PROTECTION -j ACCEPT
    
    success "SSH暴力破解保护已设置"
}

# 应用iptables规则
apply_firewall_rules() {
    info "应用iptables防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 防火墙规则预览:"
        show_rules_preview
        return 0
    fi
    
    # 设置默认策略（先设为ACCEPT避免锁定）
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 基础规则：允许回环接口
    iptables -A INPUT -i lo -j ACCEPT
    
    # 基础规则：允许已建立和相关的连接
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # ICMP支持（网络诊断）
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT
    
    # SSH保护
    setup_ssh_protection
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j SSH_PROTECTION
    
    # 开放代理端口（TCP和UDP）
    for port in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        debug_log "开放端口: $port (TCP/UDP)"
    done
    
    # 应用NAT规则（端口跳跃）
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "应用端口跳跃规则..."
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                # 解析端口范围
                local start_port=$(echo "$port_range" | cut -d'-' -f1)
                local end_port=$(echo "$port_range" | cut -d'-' -f2)
                
                # 添加DNAT规则
                iptables -t nat -A PREROUTING -p udp --dport "$start_port:$end_port" -j DNAT --to-destination ":$target_port"
                iptables -t nat -A PREROUTING -p tcp --dport "$start_port:$end_port" -j DNAT --to-destination ":$target_port"
                
                # 开放端口范围
                iptables -A INPUT -p tcp --dport "$start_port:$end_port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$start_port:$end_port" -j ACCEPT
                
                success "应用端口跳跃: $port_range -> $target_port"
                debug_log "NAT规则: $start_port:$end_port -> $target_port"
            else
                warning "无法解析NAT规则: $rule"
            fi
        done
    fi
    
    # 记录并拒绝其他连接（限制日志频率）
    iptables -A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "iptables-drop: " --log-level 4
    
    # 最后设置默认拒绝策略
    iptables -P INPUT DROP
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "iptables规则应用成功"
    
    # 保存规则
    save_iptables_rules
}

# 保存iptables规则
save_iptables_rules() {
    info "保存iptables规则..."
    
    # 根据不同发行版保存规则
    if command -v iptables-save >/dev/null 2>&1; then
        if [ -d "/etc/iptables" ]; then
            # Debian/Ubuntu系统
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            
            # 创建启动脚本
            cat > /etc/systemd/system/iptables-restore.service << 'EOF'
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
EOF
            systemctl enable iptables-restore.service >/dev/null 2>&1 || true
            
        elif [ -d "/etc/sysconfig" ]; then
            # CentOS/RHEL系统
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            systemctl enable iptables >/dev/null 2>&1 || true
            
        else
            # 通用保存方法
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
        success "iptables规则已保存"
    else
        warning "无法保存iptables规则，重启后规则将丢失"
    fi
}

# 显示规则预览
show_rules_preview() {
    echo -e "${CYAN}📋 将要应用的iptables规则预览:${RESET}"
    echo
    echo "# 基础规则"
    echo "iptables -P INPUT DROP"
    echo "iptables -P FORWARD DROP"
    echo "iptables -P OUTPUT ACCEPT"
    echo "iptables -A INPUT -i lo -j ACCEPT"
    echo "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo
    echo "# ICMP支持"
    echo "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT"
    echo
    echo "# SSH保护"
    echo "iptables -A INPUT -p tcp --dport $SSH_PORT -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP"
    echo "iptables -A INPUT -p tcp --dport $SSH_PORT -m recent --name ssh_attempts --set -j ACCEPT"
    echo
    echo "# 代理端口"
    for port in "${DETECTED_PORTS[@]}"; do
        echo "iptables -A INPUT -p tcp --dport $port -j ACCEPT"
        echo "iptables -A INPUT -p udp --dport $port -j ACCEPT"
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo
        echo "# 端口跳跃规则"
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            local start_port=$(echo "$port_range" | cut -d'-' -f1)
            local end_port=$(echo "$port_range" | cut -d'-' -f2)
            echo "iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
            echo "iptables -t nat -A PREROUTING -p tcp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
            echo "iptables -A INPUT -p tcp --dport $start_port:$end_port -j ACCEPT"
            echo "iptables -A INPUT -p udp --dport $start_port:$end_port -j ACCEPT"
        done
    fi
    
    echo
    echo "# 日志和拒绝"
    echo "iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix 'iptables-drop: '"
    echo "iptables -A INPUT -j DROP"
}

# 验证端口跳跃功能
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "验证端口跳跃配置..."
        
        echo -e "\n${CYAN}🔍 当前NAT规则状态:${RESET}"
        if command -v iptables >/dev/null 2>&1; then
            iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep DNAT || echo "无NAT规则"
        fi
        
        echo -e "\n${YELLOW}💡 端口跳跃使用说明:${RESET}"
        echo -e "  - 客户端可以连接到端口范围内的任意端口"
        echo -e "  - 所有连接都会转发到目标端口"
        echo -e "  - 例如: 连接范围内任意端口都会转发到目标端口"
        
        # 检查目标端口是否在监听
        local checked_ports=()
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            debug_log "验证规则: $port_range -> $target_port"
            
            if [ -n "$target_port" ]; then
                # 避免重复检查同一个端口
                if [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                    checked_ports+=("$target_port")
                    
                    if ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                        echo -e "  ${GREEN}✓ 目标端口 $target_port 正在监听${RESET}"
                    else
                        echo -e "  ${YELLOW}⚠️  目标端口 $target_port 未在监听${RESET}"
                        echo -e "    ${YELLOW}提示: 请确保代理服务在端口 $target_port 上运行${RESET}"
                    fi
                fi
            else
                echo -e "  ${RED}❌ 无法解析规则: $rule${RESET}"
            fi
        done
        
        echo -e "\n${CYAN}📝 端口跳跃规则汇总:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• 端口范围 $port_range → 目标端口 $target_port${RESET}"
        done
    fi
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙到默认状态${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}警告: 这将清除所有iptables规则！${RESET}"
        echo -e "${YELLOW}确认重置防火墙? [y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            info "取消重置操作"
            return 0
        fi
    fi
    
    info "重置iptables规则..."
    
    if [ "$DRY_RUN" = false ]; then
        # 设置默认策略为ACCEPT
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        # 清空所有规则
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        
        # 保存空规则
        save_iptables_rules
        
        success "防火墙已重置到默认状态"
    else
        info "[预演模式] 将重置所有iptables规则"
    fi
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}🔍 当前防火墙状态${RESET}"
    echo
    
    echo -e "${GREEN}📊 iptables规则统计:${RESET}"
    local input_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | wc -l)
    local nat_rules=$(iptables -t nat -L PREROUTING --line-numbers 2>/dev/null | wc -l)
    echo -e "  INPUT规则数: $((input_rules - 2))"
    echo -e "  NAT规则数: $((nat_rules - 2))"
    echo
    
    echo -e "${GREEN}🔓 开放端口:${RESET}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E "dpt:[0-9]+" | while read -r line; do
        local port=$(echo "$line" | grep -oE "dpt:[0-9]+" | cut -d: -f2)
        local protocol=$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
        if [ -n "$port" ]; then
            echo -e "  • $port ($protocol)"
        fi
    done
    echo
    
    echo -e "${GREEN}🔄 端口跳跃规则:${RESET}"
    local nat_count=0
    while read -r line; do
        if echo "$line" | grep -q "DNAT"; then
            nat_count=$((nat_count + 1))
            local port_range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | cut -d: -f2-)
            local target=$(echo "$line" | grep -oE "to:[0-9\.]+:[0-9]+" | cut -d: -f2-)
            if [ -n "$port_range" ] && [ -n "$target" ]; then
                echo -e "  • $port_range → $target"
            fi
        fi
    done <<< "$(iptables -t nat -L PREROUTING -n -v 2>/dev/null)"
    
    if [ "$nat_count" -eq 0 ]; then
        echo -e "  ${YELLOW}无端口跳跃规则${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🛡️  SSH保护状态:${RESET}"
    if iptables -L INPUT -n 2>/dev/null | grep -q "recent:"; then
        echo -e "  ${GREEN}✓ SSH暴力破解保护已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  SSH暴力破解保护未启用${RESET}"
    fi
    echo
    
    echo -e "${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}查看NAT规则:${RESET} iptables -t nat -L -n -v"
    echo -e "  ${YELLOW}查看监听端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}重新配置:${RESET} bash $0"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 iptables防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口数量: $OPENED_PORTS${RESET}"
    echo -e "  ${GREEN}✓ SSH端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙引擎: iptables${RESET}"
    echo -e "  ${GREEN}✓ 内部服务保护: 已启用${RESET}"
    echo -e "  ${GREEN}✓ 默认端口: 80, 443 (恒定开放)${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓ 端口跳跃规则: ${#unique_nat_rules[@]} 个${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放的端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认开放${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• $port_range → $target_port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 这是预演模式，实际未修改防火墙${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}查看NAT规则:${RESET} iptables -t nat -L -n -v"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加端口跳跃:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 代理端口已精准开放，端口跳跃已配置，内部服务已保护，服务器安全防护已启用！${RESET}"
    
    # 如果有未监听的目标端口，给出提醒
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local has_unlistened=false
        local checked_ports=()
        
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ] && [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                checked_ports+=("$target_port")
                if ! ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                    has_unlistened=true
                    break
                fi
            fi
        done
        
        if [ "$has_unlistened" = true ]; then
            echo -e "\n${YELLOW}⚠️  提醒: 检测到部分端口跳跃的目标端口未在监听${RESET}"
            echo -e "${YELLOW}   请确保相关代理服务正在运行，否则端口跳跃功能可能无效${RESET}"
        fi
    fi
}

# 主函数
main() {
    # 信号处理
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    # 解析参数
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始智能代理端口检测和配置...${RESET}"
    
    # 1. 系统检查
    check_system
    
    # 2. 检测SSH端口
    detect_ssh_port
    
    # 3. 检测现有NAT规则
    detect_existing_nat_rules
    
    # 4. 清理现有防火墙（保留NAT）
    cleanup_firewalls
    
    # 5. 检测代理进程
    if ! detect_proxy_processes; then
        warning "建议启动代理服务后再运行此脚本以获得最佳效果"
    fi
    
    # 6. 解析配置文件端口
    parse_config_ports
    
    # 7. 检测监听端口
    detect_listening_ports
    
    # 8. 端口过滤和确认
    if ! filter_and_confirm_ports; then
        info "添加Hiddify常用端口作为备选..."
        DETECTED_PORTS=("${HIDDIFY_COMMON_PORTS[@]}")
        if ! filter_and_confirm_ports; then
            error_exit "无法确定需要开放的端口"
        fi
    fi
    
    # 9. 应用防火墙规则
    apply_firewall_rules
    
    # 10. 验证端口跳跃功能
    verify_port_hopping
    
    # 11. 显示最终状态
    show_final_status
}

# 脚本入口
main "$@")
            
            # 提取进程名
            local process="unknown"
            if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
                process="${BASH_REMATCH[1]}"
            fi
            
            # 检查是否是公网监听的代理端口
            if [[ "$address_port" =~ ^(0\.0\.0\.0|\*|\[::\]|::): ]] && is_proxy_related "$process" && [ -n "$port" ]; then
                # 排除SSH和常见Web端口
                if [ "$port" != "$SSH_PORT" ] && [ "$port" != "80" ] && [ "$port" != "443" ]; then
                    listening_proxy_ports+=("$port:$process")
                    debug_log "发现代理监听端口: $port ($process)"
                fi
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    # 为每个代理端口生成端口跳跃建议
    for port_info in "${listening_proxy_ports[@]}"; do
        local target_port=$(echo "$port_info" | cut -d':' -f1)
        local process=$(echo "$port_info" | cut -d':' -f2)
        
        # 根据端口号生成合适的端口范围建议
        local base_port=$target_port
        local start_port end_port
        
        # 智能选择端口范围
        if [ "$target_port" -lt 10000 ]; then
            # 对于低端口，使用高端口范围
            start_port=$((40000 + (target_port % 1000) * 100))
            end_port=$((start_port + 99))
        else
            # 对于高端口，在附近创建范围
            start_port=$((target_port + 1000))
            end_port=$((start_port + 199))
        fi
        
        # 确保端口范围不超过65535
        if [ "$end_port" -gt 65535 ]; then
            end_port=65535
            start_port=$((end_port - 199))
        fi
        
        # 检查是否已存在类似的端口跳跃规则
        local rule_exists=false
        for existing_rule in "${NAT_RULES[@]}"; do
            local existing_target=$(split_nat_rule "$existing_rule" "->" "2")
            if [ "$existing_target" = "$target_port" ]; then
                rule_exists=true
                break
            fi
        done
        
        if [ "$rule_exists" = false ]; then
            local suggestion="$start_port-$end_port->$target_port"
            suggestions+=("$suggestion:$process")
            debug_log "生成端口跳跃建议: $start_port-$end_port -> $target_port (用于 $process)"
        fi
    done
    
    # 显示建议并询问用户是否应用
    if [ ${#suggestions[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🤖 智能端口跳跃规则建议:${RESET}"
        echo -e "${YELLOW}基于检测到的代理服务，建议配置以下端口跳跃规则:${RESET}"
        
        local i=1
        for suggestion in "${suggestions[@]}"; do
            local rule=$(echo "$suggestion" | cut -d':' -f1)
            local process=$(echo "$suggestion" | cut -d':' -f2)
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            echo -e "  ${CYAN}$i. 端口范围 $port_range → 目标端口 $target_port (用于 $process 服务)${RESET}"
            i=$((i + 1))
        done
        
        echo -e "\n${YELLOW}这些端口跳跃规则的作用:${RESET}"
        echo -e "  ${YELLOW}• 增加连接的随机性，提高抗封锁能力${RESET}"
        echo -e "  ${YELLOW}• 客户端可以连接范围内任意端口${RESET}"
        echo -e "  ${YELLOW}• 流量会自动转发到实际的代理服务端口${RESET}"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "\n${YELLOW}是否应用这些智能建议的端口跳跃规则? [Y/n]${RESET}"
            read -r response
            if [[ ! "$response" =~ ^[Nn]([oO])?$ ]]; then
                for suggestion in "${suggestions[@]}"; do
                    local rule=$(echo "$suggestion" | cut -d':' -f1)
                    NAT_RULES+=("$rule")
                    
                    # 确保目标端口在检测端口列表中
                    local target_port=$(split_nat_rule "$rule" "->" "2")
                    if [[ ! " ${DETECTED_PORTS[*]} " =~ " $target_port " ]]; then
                        DETECTED_PORTS+=("$target_port")
                    fi
                done
                success "已添加 ${#suggestions[@]} 个智能推荐的端口跳跃规则"
            else
                info "跳过智能推荐的端口跳跃规则"
            fi
        fi
    else
        debug_log "没有生成端口跳跃建议（可能已存在规则或无合适的代理端口）"
    fi
}
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口跳跃规则${RESET}"
    echo -e "${YELLOW}端口跳跃允许将一个端口范围转发到单个目标端口${RESET}"
    echo -e "${YELLOW}例如: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}请输入端口范围 (格式: 起始端口-结束端口，如 16820-16888):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_port="${BASH_REMATCH[1]}"
            local end_port="${BASH_REMATCH[2]}"
            
            if [ "$start_port" -ge "$end_port" ]; then
                error_exit "起始端口必须小于结束端口"
            fi
            
            echo -e "${CYAN}请输入目标端口 (单个端口号):${RESET}"
            read -r target_port
            
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                DETECTED_PORTS+=("$target_port")
                success "添加端口跳跃规则: $port_range -> $target_port"
                
                echo -e "${YELLOW}是否继续添加其他端口跳跃规则? [y/N]${RESET}"
                read -r response
                if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    break
                fi
            else
                echo -e "${RED}无效的目标端口: $target_port${RESET}"
            fi
        else
            echo -e "${RED}无效的端口范围格式: $port_range${RESET}"
        fi
    done
}

# 智能检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found_processes=()
    
    # 检查核心代理进程
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现代理进程: $process"
        fi
    done
    
    # 检查Web面板进程
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现Web面板进程: $process"
        fi
    done
    
    if [ ${#found_processes[@]} -gt 0 ]; then
        success "检测到代理相关进程: ${found_processes[*]}"
        return 0
    else
        warning "未检测到运行中的代理进程"
        return 1
    fi
}

# 检查绑定地址类型
check_bind_address() {
    local address="$1"
    
    # 检查是否是公网监听地址
    if [[ "$address" =~ ^(\*|0\.0\.0\.0|\[::\]|::): ]]; then
        echo "public"
    # 检查是否是本地回环地址
    elif [[ "$address" =~ ^(127\.|::1|\[::1\]): ]]; then
        echo "localhost"
    # 检查是否是内网地址
    elif [[ "$address" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.): ]]; then
        echo "private"
    # 其他情况
    else
        echo "unknown"
    fi
}

# 从配置文件解析端口
parse_config_ports() {
    info "解析配置文件中的端口..."
    
    local config_ports=()
    
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "分析配置文件: $config_file"
            
            # 根据文件类型解析端口
            if [[ "$config_file" =~ \.json$ ]]; then
                # JSON配置文件
                if command -v jq >/dev/null 2>&1; then
                    # 更精确的JSON解析，查找inbounds中的公网监听端口
                    local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析到公网端口: $port"
                        done <<< "$ports"
                    fi
                    
                    # 也检查简单的port字段
                    local simple_ports=$(jq -r '.. | objects | select(has("port")) | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$simple_ports" ]; then
                        while read -r port; do
                            # 只添加不在内部服务端口列表中的端口
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 解析到端口: $port"
                            else
                                debug_log "跳过内部服务端口: $port"
                            fi
                        done <<< "$simple_ports"
                    fi
                else
                    # 简单文本解析
                    local ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 文本解析到端口: $port"
                            fi
                        done <<< "$ports"
                    fi
                fi
            elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                # YAML配置文件
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file YAML解析到端口: $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    # 去重并存储
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从配置文件解析到 ${#unique_ports[@]} 个端口"
    fi
}

# 检测监听端口（改进版）
detect_listening_ports() {
    info "检测当前监听端口..."
    
    local listening_ports=()
    local localhost_ports=()
    
    # 使用ss命令检测
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local protocol=$(echo "$line" | awk '{print tolower($1)}')
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            
            # 提取端口号
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            
            # 提取进程名
            local process="unknown"
            if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
                process="${BASH_REMATCH[1]}"
            fi
            
            # 检查绑定地址类型
            local bind_type=$(check_bind_address "$address_port")
            
            debug_log "检测到监听: $address_port ($protocol, $process, $bind_type)"
            
            # 检查是否是代理相关进程
            if is_proxy_related "$process" && [ -n "$port" ] && [ "$port" != "$SSH_PORT" ]; then
                if [ "$bind_type" = "public" ]; then
                    # 公网监听端口
                    if ! is_internal_service_port "$port"; then
                        listening_ports+=("$port")
                        debug_log "检测到公网代理端口: $port ($protocol, $process)"
                    else
                        debug_log "跳过内部服务端口: $port"
                    fi
                elif [ "$bind_type" = "localhost" ]; then
                    # 本地监听端口（记录但不开放）
                    localhost_ports+=("$port")
                    debug_log "检测到本地代理端口: $port ($protocol, $process) - 不对外开放"
                fi
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    # 显示本地监听端口信息
    if [ ${#localhost_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 检测到内部服务端口 (仅本地监听):${RESET}"
        for port in $(printf '%s\n' "${localhost_ports[@]}" | sort -nu); do
            echo -e "  ${YELLOW}• $port${RESET} - 内部服务，不对外开放"
        done
    fi
    
    # 去重并添加到检测列表
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "检测到 ${#unique_ports[@]} 个公网监听端口"
    fi
}

# 判断是否是代理相关进程
is_proxy_related() {
    local process="$1"
    
    # 精确匹配
    for proxy_proc in "${PROXY_CORE_PROCESSES[@]}" "${WEB_PANEL_PROCESSES[@]}"; do
        if [[ "$process" == *"$proxy_proc"* ]]; then
            return 0
        fi
    done
    
    # 模糊匹配常见代理关键词
    if [[ "$process" =~ (proxy|vpn|tunnel|shadowsocks|trojan|v2ray|xray|clash|hysteria|sing) ]]; then
        return 0
    fi
    
    return 1
}

# 检查是否是内部服务端口
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# 检查是否是标准代理端口
is_standard_proxy_port() {
    local port="$1"
    
    # 检查常用代理端口
    local common_ports=(80 443 1080 1085 8080 8388 8443 8880 8888 9443)
    for common_port in "${common_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    # 检查高端口范围（10000-10999, 30000-39999）- 但排除已知内部端口
    if [ "$port" -ge 30000 ] && [ "$port" -le 39999 ]; then
        return 0
    fi
    if [ "$port" -ge 40000 ] && [ "$port" -le 65000 ] && ! is_internal_service_port "$port"; then
        return 0
    fi
    
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    # 检查是否在黑名单中
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then
            debug_log "端口 $port 在黑名单中"
            return 1
        fi
    done
    
    # 检查是否是内部服务端口
    if is_internal_service_port "$port"; then
        debug_log "端口 $port 是内部服务端口"
        return 1
    fi
    
    # 端口范围检查
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        debug_log "端口 $port 超出有效范围"
        return 1
    fi
    
    # 默认开放端口（80, 443）始终安全
    if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
        debug_log "端口 $port 是默认开放端口"
        return 0
    fi
    
    return 0
}

# 智能端口过滤和确认
filter_and_confirm_ports() {
    info "智能端口分析和确认..."
    
    # 添加默认开放端口（80、443）
    info "添加默认开放端口: ${DEFAULT_OPEN_PORTS[*]}"
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    # 去重所有检测到的端口
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    local suspicious_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
    # 分类端口
    for port in "${all_ports[@]}"; do
        if ! is_port_safe "$port"; then
            if is_internal_service_port "$port"; then
                internal_ports+=("$port")
            else
                unsafe_ports+=("$port")
            fi
        elif is_standard_proxy_port "$port" || [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
            safe_ports+=("$port")
        else
            # 其他端口需要进一步检查
            suspicious_ports+=("$port")
        fi
    done
    
    # 显示检测结果
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 标准代理端口 (推荐开放):${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} - 默认开放端口"
            else
                echo -e "  ${GREEN}✓ $port${RESET} - 常见代理端口"
            fi
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 内部服务端口 (已过滤):${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "  ${YELLOW}- $port${RESET} - 内部服务端口，不对外开放"
        done
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}⚠️  可疑端口 (建议确认):${RESET}"
        for port in "${suspicious_ports[@]}"; do
            echo -e "  ${YELLOW}? $port${RESET} - 不是标准代理端口"
        done
        
        echo -e "\n${YELLOW}这些端口可能不是必需的代理端口，建议确认后再开放${RESET}"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}是否也要开放这些可疑端口? [y/N]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                safe_ports+=("${suspicious_ports[@]}")
                info "用户确认开放可疑端口"
            else
                info "跳过可疑端口"
            fi
        fi
    fi
    
    if [ ${#unsafe_ports[@]} -gt 0 ]; then
        echo -e "\n${RED}❌ 危险端口 (已跳过):${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "  ${RED}✗ $port${RESET} - 系统端口或危险端口"
        done
    fi
    
    # 询问用户是否需要配置端口跳跃
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 是否需要配置端口跳跃功能? [y/N]${RESET}"
        echo -e "${YELLOW}端口跳跃可以将一个端口范围转发到单个目标端口${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    # 用户最终确认
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "没有检测到需要开放的标准代理端口"
        # 至少开放默认端口
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}📋 最终将开放以下端口:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (默认开放)"
            else
                echo -e "  ${CYAN}• $port${RESET}"
            fi
        done
        
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
            for rule in "${NAT_RULES[@]}"; do
                echo -e "  ${CYAN}• $rule${RESET}"
            done
        fi
        
        echo -e "\n${YELLOW}确认开放以上 ${#safe_ports[@]} 个端口"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "以及 ${#NAT_RULES[@]} 个端口跳跃规则"
        fi
        echo -e "? [Y/n]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]?$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    # 更新全局端口列表（去重）
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 将清理现有防火墙"
        return 0
    fi
    
    # 停用其他防火墙服务
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "已停用 $service"
        fi
    done
    
    # 重置UFW（如果存在）
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 备份现有NAT规则到临时文件
    local nat_backup="/tmp/nat_rules_backup.txt"
    iptables-save -t nat > "$nat_backup" 2>/dev/null || true
    
    # 清理filter表规则但保留基本策略
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F INPUT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    
    # 清理自定义链
    iptables -X 2>/dev/null || true
    
    success "防火墙清理完成（保留NAT规则）"
}

# 创建SSH暴力破解保护
setup_ssh_protection() {
    info "设置SSH暴力破解保护..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 将设置SSH保护"
        return 0
    fi
    
    # 创建SSH保护链
    iptables -N SSH_PROTECTION 2>/dev/null || true
    iptables -F SSH_PROTECTION 2>/dev/null || true
    
    # SSH暴力破解保护规则
    # 允许已建立的连接
    iptables -A SSH_PROTECTION -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 限制新SSH连接频率（每分钟最多3次尝试）
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --set
    
    # 接受符合频率限制的SSH连接
    iptables -A SSH_PROTECTION -j ACCEPT
    
    success "SSH暴力破解保护已设置"
}

# 应用iptables规则
apply_firewall_rules() {
    info "应用iptables防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 防火墙规则预览:"
        show_rules_preview
        return 0
    fi
    
    # 设置默认策略（先设为ACCEPT避免锁定）
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 基础规则：允许回环接口
    iptables -A INPUT -i lo -j ACCEPT
    
    # 基础规则：允许已建立和相关的连接
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # ICMP支持（网络诊断）
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT
    
    # SSH保护
    setup_ssh_protection
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j SSH_PROTECTION
    
    # 开放代理端口（TCP和UDP）
    for port in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        debug_log "开放端口: $port (TCP/UDP)"
    done
    
    # 应用NAT规则（端口跳跃）
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "应用端口跳跃规则..."
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                # 解析端口范围
                local start_port=$(echo "$port_range" | cut -d'-' -f1)
                local end_port=$(echo "$port_range" | cut -d'-' -f2)
                
                # 添加DNAT规则
                iptables -t nat -A PREROUTING -p udp --dport "$start_port:$end_port" -j DNAT --to-destination ":$target_port"
                iptables -t nat -A PREROUTING -p tcp --dport "$start_port:$end_port" -j DNAT --to-destination ":$target_port"
                
                # 开放端口范围
                iptables -A INPUT -p tcp --dport "$start_port:$end_port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$start_port:$end_port" -j ACCEPT
                
                success "应用端口跳跃: $port_range -> $target_port"
                debug_log "NAT规则: $start_port:$end_port -> $target_port"
            else
                warning "无法解析NAT规则: $rule"
            fi
        done
    fi
    
    # 记录并拒绝其他连接（限制日志频率）
    iptables -A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "iptables-drop: " --log-level 4
    
    # 最后设置默认拒绝策略
    iptables -P INPUT DROP
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "iptables规则应用成功"
    
    # 保存规则
    save_iptables_rules
}

# 保存iptables规则
save_iptables_rules() {
    info "保存iptables规则..."
    
    # 根据不同发行版保存规则
    if command -v iptables-save >/dev/null 2>&1; then
        if [ -d "/etc/iptables" ]; then
            # Debian/Ubuntu系统
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            
            # 创建启动脚本
            cat > /etc/systemd/system/iptables-restore.service << 'EOF'
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
EOF
            systemctl enable iptables-restore.service >/dev/null 2>&1 || true
            
        elif [ -d "/etc/sysconfig" ]; then
            # CentOS/RHEL系统
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            systemctl enable iptables >/dev/null 2>&1 || true
            
        else
            # 通用保存方法
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
        success "iptables规则已保存"
    else
        warning "无法保存iptables规则，重启后规则将丢失"
    fi
}

# 显示规则预览
show_rules_preview() {
    echo -e "${CYAN}📋 将要应用的iptables规则预览:${RESET}"
    echo
    echo "# 基础规则"
    echo "iptables -P INPUT DROP"
    echo "iptables -P FORWARD DROP"
    echo "iptables -P OUTPUT ACCEPT"
    echo "iptables -A INPUT -i lo -j ACCEPT"
    echo "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo
    echo "# ICMP支持"
    echo "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT"
    echo
    echo "# SSH保护"
    echo "iptables -A INPUT -p tcp --dport $SSH_PORT -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP"
    echo "iptables -A INPUT -p tcp --dport $SSH_PORT -m recent --name ssh_attempts --set -j ACCEPT"
    echo
    echo "# 代理端口"
    for port in "${DETECTED_PORTS[@]}"; do
        echo "iptables -A INPUT -p tcp --dport $port -j ACCEPT"
        echo "iptables -A INPUT -p udp --dport $port -j ACCEPT"
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo
        echo "# 端口跳跃规则"
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            local start_port=$(echo "$port_range" | cut -d'-' -f1)
            local end_port=$(echo "$port_range" | cut -d'-' -f2)
            echo "iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
            echo "iptables -t nat -A PREROUTING -p tcp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
            echo "iptables -A INPUT -p tcp --dport $start_port:$end_port -j ACCEPT"
            echo "iptables -A INPUT -p udp --dport $start_port:$end_port -j ACCEPT"
        done
    fi
    
    echo
    echo "# 日志和拒绝"
    echo "iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix 'iptables-drop: '"
    echo "iptables -A INPUT -j DROP"
}

# 验证端口跳跃功能
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "验证端口跳跃配置..."
        
        echo -e "\n${CYAN}🔍 当前NAT规则状态:${RESET}"
        if command -v iptables >/dev/null 2>&1; then
            iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep DNAT || echo "无NAT规则"
        fi
        
        echo -e "\n${YELLOW}💡 端口跳跃使用说明:${RESET}"
        echo -e "  - 客户端可以连接到端口范围内的任意端口"
        echo -e "  - 所有连接都会转发到目标端口"
        echo -e "  - 例如: 连接范围内任意端口都会转发到目标端口"
        
        # 检查目标端口是否在监听
        local checked_ports=()
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            debug_log "验证规则: $port_range -> $target_port"
            
            if [ -n "$target_port" ]; then
                # 避免重复检查同一个端口
                if [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                    checked_ports+=("$target_port")
                    
                    if ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                        echo -e "  ${GREEN}✓ 目标端口 $target_port 正在监听${RESET}"
                    else
                        echo -e "  ${YELLOW}⚠️  目标端口 $target_port 未在监听${RESET}"
                        echo -e "    ${YELLOW}提示: 请确保代理服务在端口 $target_port 上运行${RESET}"
                    fi
                fi
            else
                echo -e "  ${RED}❌ 无法解析规则: $rule${RESET}"
            fi
        done
        
        echo -e "\n${CYAN}📝 端口跳跃规则汇总:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• 端口范围 $port_range → 目标端口 $target_port${RESET}"
        done
    fi
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙到默认状态${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}警告: 这将清除所有iptables规则！${RESET}"
        echo -e "${YELLOW}确认重置防火墙? [y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            info "取消重置操作"
            return 0
        fi
    fi
    
    info "重置iptables规则..."
    
    if [ "$DRY_RUN" = false ]; then
        # 设置默认策略为ACCEPT
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        # 清空所有规则
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        
        # 保存空规则
        save_iptables_rules
        
        success "防火墙已重置到默认状态"
    else
        info "[预演模式] 将重置所有iptables规则"
    fi
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}🔍 当前防火墙状态${RESET}"
    echo
    
    echo -e "${GREEN}📊 iptables规则统计:${RESET}"
    local input_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | wc -l)
    local nat_rules=$(iptables -t nat -L PREROUTING --line-numbers 2>/dev/null | wc -l)
    echo -e "  INPUT规则数: $((input_rules - 2))"
    echo -e "  NAT规则数: $((nat_rules - 2))"
    echo
    
    echo -e "${GREEN}🔓 开放端口:${RESET}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E "dpt:[0-9]+" | while read -r line; do
        local port=$(echo "$line" | grep -oE "dpt:[0-9]+" | cut -d: -f2)
        local protocol=$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
        if [ -n "$port" ]; then
            echo -e "  • $port ($protocol)"
        fi
    done
    echo
    
    echo -e "${GREEN}🔄 端口跳跃规则:${RESET}"
    local nat_count=0
    while read -r line; do
        if echo "$line" | grep -q "DNAT"; then
            nat_count=$((nat_count + 1))
            local port_range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | cut -d: -f2-)
            local target=$(echo "$line" | grep -oE "to:[0-9\.]+:[0-9]+" | cut -d: -f2-)
            if [ -n "$port_range" ] && [ -n "$target" ]; then
                echo -e "  • $port_range → $target"
            fi
        fi
    done <<< "$(iptables -t nat -L PREROUTING -n -v 2>/dev/null)"
    
    if [ "$nat_count" -eq 0 ]; then
        echo -e "  ${YELLOW}无端口跳跃规则${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🛡️  SSH保护状态:${RESET}"
    if iptables -L INPUT -n 2>/dev/null | grep -q "recent:"; then
        echo -e "  ${GREEN}✓ SSH暴力破解保护已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  SSH暴力破解保护未启用${RESET}"
    fi
    echo
    
    echo -e "${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}查看NAT规则:${RESET} iptables -t nat -L -n -v"
    echo -e "  ${YELLOW}查看监听端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}重新配置:${RESET} bash $0"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 iptables防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口数量: $OPENED_PORTS${RESET}"
    echo -e "  ${GREEN}✓ SSH端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙引擎: iptables${RESET}"
    echo -e "  ${GREEN}✓ 内部服务保护: 已启用${RESET}"
    echo -e "  ${GREEN}✓ 默认端口: 80, 443 (恒定开放)${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓ 端口跳跃规则: ${#unique_nat_rules[@]} 个${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放的端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认开放${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• $port_range → $target_port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 这是预演模式，实际未修改防火墙${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}查看NAT规则:${RESET} iptables -t nat -L -n -v"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加端口跳跃:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 代理端口已精准开放，端口跳跃已配置，内部服务已保护，服务器安全防护已启用！${RESET}"
    
    # 如果有未监听的目标端口，给出提醒
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local has_unlistened=false
        local checked_ports=()
        
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ] && [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                checked_ports+=("$target_port")
                if ! ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                    has_unlistened=true
                    break
                fi
            fi
        done
        
        if [ "$has_unlistened" = true ]; then
            echo -e "\n${YELLOW}⚠️  提醒: 检测到部分端口跳跃的目标端口未在监听${RESET}"
            echo -e "${YELLOW}   请确保相关代理服务正在运行，否则端口跳跃功能可能无效${RESET}"
        fi
    fi
}

# 主函数
main() {
    # 信号处理
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    # 解析参数
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始智能代理端口检测和配置...${RESET}"
    
    # 1. 系统检查
    check_system
    
    # 2. 检测SSH端口
    detect_ssh_port
    
    # 3. 检测现有NAT规则
    detect_existing_nat_rules
    
    # 4. 清理现有防火墙（保留NAT）
    cleanup_firewalls
    
    # 5. 检测代理进程
    if ! detect_proxy_processes; then
        warning "建议启动代理服务后再运行此脚本以获得最佳效果"
    fi
    
    # 6. 解析配置文件端口
    parse_config_ports
    
    # 7. 检测监听端口
    detect_listening_ports
    
    # 8. 端口过滤和确认
    if ! filter_and_confirm_ports; then
        info "添加Hiddify常用端口作为备选..."
        DETECTED_PORTS=("${HIDDIFY_COMMON_PORTS[@]}")
        if ! filter_and_confirm_ports; then
            error_exit "无法确定需要开放的端口"
        fi
    fi
    
    # 9. 应用防火墙规则
    apply_firewall_rules
    
    # 10. 验证端口跳跃功能
    verify_port_hopping
    
    # 11. 显示最终状态
    show_final_status
}

# 脚本入口
main "$@"
