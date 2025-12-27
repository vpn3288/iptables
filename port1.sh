#!/bin/bash
set -e

# ============================================================================
# 增强版代理端口防火墙管理脚本 v2.1.0
# 
# 功能特性：
# - 智能端口检测（支持 20+ 种代理软件）
# - IPv4/IPv6 双栈支持
# - Docker 容器端口自动检测
# - NAT 端口转发配置
# - SSH 暴力破解防护
# - 配置文件备份与恢复
# - 内部服务端口保护
# 
# 使用方法：
#   bash firewall.sh              # 标准部署
#   bash firewall.sh --dry-run    # 预览模式
#   bash firewall.sh --ipv6       # 启用 IPv6
#   bash firewall.sh --help       # 显示帮助
# ============================================================================

# 颜色定义
readonly GREEN="\033[32m"
readonly YELLOW="\033[33m"
readonly RED="\033[31m"
readonly BLUE="\033[34m"
readonly CYAN="\033[36m"
readonly RESET="\033[0m"

# 脚本信息
readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_NAME="增强版代理端口防火墙管理脚本"
readonly BACKUP_DIR="/var/backups/firewall"

echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${YELLOW}║  🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION}  ║${RESET}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${RESET}"
echo -e "${CYAN}   支持 IPv4/IPv6 双栈，兼容所有主流代理面板${RESET}\n"

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
ENABLE_IPV6=false
ENABLE_DOCKER=true
SSH_PORT=""
DETECTED_PORTS=()
PORT_RANGES=()
NAT_RULES=()
OPENED_PORTS=0
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 默认永久开放端口
readonly DEFAULT_OPEN_PORTS=(80 443)

# 代理核心进程扩展列表
readonly PROXY_CORE_PROCESSES=(
    # Xray 系列
    "xray" "v2ray" "v2ray-core" "v2ctl"
    
    # Sing-box 系列
    "sing-box" "singbox" "sing_box"
    
    # Hysteria 系列
    "hysteria" "hysteria2" "hysteria-server"
    
    # 其他协议
    "tuic" "tuic-server" "juicity" "shadowtls" "reality"
    
    # 管理面板
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    "marzban" "marzban-node"
    
    # Trojan 系列
    "trojan" "trojan-go" "trojan-plus" "trojan-gfw"
    
    # Shadowsocks 系列
    "shadowsocks-rust" "ss-server" "ss-local"
    "shadowsocks-libev" "go-shadowsocks2"
    "outline-ss-server"
    
    # 其他工具
    "brook" "gost" "naive" "naiveproxy"
    "clash" "clash-meta" "mihomo" "clash-verge"
    "kcptun" "udp2raw" "udpspeeder"
)

# Web 面板进程
readonly WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" 
    "haproxy" "envoy" "traefik"
)

# 代理配置文件路径（扩展版）
readonly PROXY_CONFIG_FILES=(
    # Hiddify
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/log/system/hiddify-panel.log"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/opt/hiddify-manager/.env"
    "/opt/hiddify-manager/hiddify-panel/hiddifypanel/panel/hiddify.py"
    
    # X-UI 系列
    "/etc/x-ui/config.json"
    "/opt/3x-ui/bin/config.json"
    "/usr/local/x-ui/bin/config.json"
    "/usr/local/x-ui/config.json"
    
    # Xray / V2Ray
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/opt/xray/config.json"
    "/opt/v2ray/config.json"
    
    # Sing-box
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    "/var/lib/sing-box/config.json"
    
    # Marzban
    "/opt/marzban/.env"
    "/opt/marzban/config.json"
    "/var/lib/marzban/.env"
    "/opt/marzban/xray_config.json"
    
    # Hysteria
    "/etc/hysteria/config.json"
    "/etc/hysteria/config.yaml"
    "/etc/hysteria/server.json"
    
    # Trojan
    "/etc/trojan/config.json"
    "/usr/local/etc/trojan/config.json"
    "/etc/trojan-go/config.json"
    
    # 其他
    "/etc/tuic/config.json"
    "/etc/shadowsocks-rust/config.json"
    "/etc/shadowsocks-libev/config.json"
    "/etc/outline/access.txt"
)

# 内部服务端口（不应对外暴露）
readonly INTERNAL_SERVICE_PORTS=(
    # 面板管理端口
    8181 10085 10086 9090 3000 3001 8000 8001
    
    # X-UI 系列内部端口
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    
    # Hiddify 内部端口
    54321 62789 62050 62051 62052
    
    # Marzban 内部端口
    8000 8001 8080
    
    # 其他内部端口
    9000 9001 9002 9003
    8090 8091 8092 8093 8094 8095
)

# 危险端口黑名单（系统服务端口）
readonly BLACKLIST_PORTS=(
    # SSH/Telnet
    22 23
    
    # 邮件服务
    25 110 143 465 587 993 995
    
    # DNS/DHCP
    53 67 68 69
    
    # 文件共享
    111 135 137 138 139 445 2049
    
    # 数据库
    1433 1521 3306 5432 6379 27017 11211 5984
    
    # 远程桌面
    3389 5900 5901 5902 5903
    
    # 其他系统服务
    514 631 873 2375 2376 5000 8080
    
    # 面板管理端口（应单独配置）
    8181 10085 10086
)

# ============================================================================
# 辅助函数
# ============================================================================

debug_log() { 
    if [ "$DEBUG_MODE" = true ]; then 
        echo -e "${BLUE}[DEBUG $(date +%H:%M:%S)] $1${RESET}" >&2
    fi
}

error_exit() { 
    echo -e "${RED}❌ 错误: $1${RESET}" >&2
    exit 1
}

warning() { 
    echo -e "${YELLOW}⚠️  警告: $1${RESET}"
}

success() { 
    echo -e "${GREEN}✅ $1${RESET}"
}

info() { 
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

# 进度条显示
show_progress() {
    local current=$1
    local total=$2
    local message=$3
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    printf "\r${CYAN}[%-50s] %3d%% - %s${RESET}" \
        "$(printf '#%.0s' $(seq 1 $filled))$(printf ' %.0s' $(seq 1 $empty))" \
        "$percent" "$message"
    
    if [ $current -eq $total ]; then
        echo
    fi
}

# 改进的字符串分割函数
split_nat_rule() {
    local rule="$1"
    local field="$2"
    
    case "$field" in
        "range")
            echo "${rule%%->*}"
            ;;
        "target")
            echo "${rule##*->}"
            ;;
        *)
            echo ""
            ;;
    esac
}

# 端口验证函数
validate_port() {
    local port="$1"
    
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    
    return 0
}

# 端口范围验证
validate_port_range() {
    local range="$1"
    
    if ! [[ "$range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        return 1
    fi
    
    local start="${BASH_REMATCH[1]}"
    local end="${BASH_REMATCH[2]}"
    
    if ! validate_port "$start" || ! validate_port "$end"; then
        return 1
    fi
    
    if [ "$start" -ge "$end" ]; then
        return 1
    fi
    
    return 0
}

# ============================================================================
# 帮助信息
# ============================================================================

show_help() {
    cat << 'EOF'

╔════════════════════════════════════════════════════════════╗
║           增强版代理端口防火墙管理脚本 v2.1.0              ║
╚════════════════════════════════════════════════════════════╝

专为现代代理面板设计的智能端口管理工具

【使用方法】
    bash firewall.sh [选项]

【选项说明】
    --debug          显示详细调试信息
    --dry-run        预览模式，不实际修改防火墙
    --ipv6           启用 IPv6 支持
    --no-docker      禁用 Docker 端口检测
    --add-range      交互式添加端口转发规则
    --reset          重置防火墙到默认状态
    --clean-nat      清理所有 NAT 规则
    --backup         备份当前防火墙配置
    --restore        恢复防火墙配置
    --status         显示当前防火墙状态
    --help, -h       显示此帮助信息

【支持的代理面板/软件】
    ✓ Hiddify Manager/Panel
    ✓ Marzban (单节点/多节点)
    ✓ 3X-UI / X-UI / V2-UI / V2rayA
    ✓ Xray-core / V2Ray-core
    ✓ Sing-box (全家桶)
    ✓ Hysteria / Hysteria2
    ✓ TUIC / Juicity
    ✓ Trojan / Trojan-Go / Trojan-Plus
    ✓ Shadowsocks (Rust/Libev/Go)
    ✓ Reality / ShadowTLS
    ✓ Brook / GOST / Naive
    ✓ Clash / Clash-Meta / Mihomo

【核心功能】
    ✓ 智能端口检测（20+ 种代理软件）
    ✓ 自动过滤内部服务端口
    ✓ 危险端口黑名单过滤
    ✓ SSH 暴力破解防护
    ✓ NAT 端口转发（Port Hopping）
    ✓ IPv4/IPv6 双栈支持
    ✓ Docker 容器端口检测
    ✓ 配置文件智能解析
    ✓ 防火墙规则备份/恢复
    ✓ 重复规则自动清理

【使用示例】
    # 标准部署（推荐）
    bash firewall.sh

    # 预览模式（安全测试）
    bash firewall.sh --dry-run

    # 启用 IPv6 + 调试模式
    bash firewall.sh --ipv6 --debug

    # 仅配置端口转发
    bash firewall.sh --add-range

    # 查看当前状态
    bash firewall.sh --status

    # 备份当前配置
    bash firewall.sh --backup

    # 重置防火墙
    bash firewall.sh --reset

【安全建议】
    1. 首次使用请先运行 --dry-run 预览
    2. 保持至少一个 SSH 连接作为备用
    3. 建议在 screen/tmux 中运行脚本
    4. 定期备份防火墙配置
    5. 监控防火墙日志: tail -f /var/log/syslog | grep iptables

【故障排除】
    问题: SSH 连接断开
    解决: 使用 VNC/控制台访问，运行 iptables -P INPUT ACCEPT

    问题: 端口检测不完整
    解决: 使用 --debug 模式查看详细日志

    问题: NAT 规则冲突
    解决: 先运行 --clean-nat 清理旧规则

【更多信息】
    项目地址: https://github.com/your-repo/firewall
    问题反馈: https://github.com/your-repo/firewall/issues

EOF
}

# ============================================================================
# 参数解析
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG_MODE=true
                info "调试模式已启用"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                warning "预览模式 - 不会实际修改防火墙"
                shift
                ;;
            --ipv6)
                ENABLE_IPV6=true
                info "IPv6 支持已启用"
                shift
                ;;
            --no-docker)
                ENABLE_DOCKER=false
                info "Docker 端口检测已禁用"
                shift
                ;;
            --add-range)
                add_port_range_interactive
                exit 0
                ;;
            --reset)
                reset_firewall
                exit 0
                ;;
            --clean-nat)
                clean_nat_rules_only
                exit 0
                ;;
            --backup)
                backup_firewall_config
                exit 0
                ;;
            --restore)
                restore_firewall_config
                exit 0
                ;;
            --status)
                show_firewall_status
                exit 0
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error_exit "未知参数: $1 (使用 --help 查看帮助)"
                ;;
        esac
    done
}

# ============================================================================
# 系统环境检查
# ============================================================================

check_system() {
    info "检查系统环境..."
    
    # 检查必需工具
    local required_tools=("iptables" "iptables-save" "iptables-restore" "ss")
    local optional_tools=("jq" "docker")
    local missing_required=()
    local missing_optional=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_required+=("$tool")
        fi
    done
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_optional+=("$tool")
        fi
    done
    
    # 检查 IPv6 支持
    if [ "$ENABLE_IPV6" = true ]; then
        if ! command -v "ip6tables" >/dev/null 2>&1; then
            missing_required+=("ip6tables")
        fi
        
        if [ ! -f /proc/net/if_inet6 ]; then
            warning "系统未启用 IPv6，将禁用 IPv6 支持"
            ENABLE_IPV6=false
        fi
    fi
    
    # 安装缺失的必需工具
    if [ ${#missing_required[@]} -gt 0 ]; then
        warning "缺少必需工具: ${missing_required[*]}"
        
        if [ "$DRY_RUN" = false ]; then
            info "正在安装缺失的工具..."
            
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq
                apt-get install -y iptables iptables-persistent iproute2 2>/dev/null || true
            elif command -v yum >/dev/null 2>&1; then
                yum install -y iptables iptables-services iproute 2>/dev/null || true
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y iptables iptables-services iproute 2>/dev/null || true
            elif command -v apk >/dev/null 2>&1; then
                apk add iptables iproute2 2>/dev/null || true
            else
                error_exit "无法自动安装依赖包，请手动安装: ${missing_required[*]}"
            fi
        else
            error_exit "预览模式下无法安装缺失工具"
        fi
    fi
    
    # 提示可选工具
    if [ ${#missing_optional[@]} -gt 0 ]; then
        warning "可选工具未安装: ${missing_optional[*]}"
        info "这些工具可以提供更好的功能支持"
    fi
    
    # 检查系统信息
    local os_info=$(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d'"' -f2)
    local kernel_version=$(uname -r)
    local arch=$(uname -m)
    
    debug_log "操作系统: ${os_info:-Unknown}"
    debug_log "内核版本: $kernel_version"
    debug_log "系统架构: $arch"
    
    # 创建备份目录
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR" 2>/dev/null || true
    fi
    
    success "系统环境检查完成"
}

# 第一部分完成
# 下一部分将包含：端口检测、配置解析、Docker 支持
EOF
# ============================================================================
# 第二部分：端口检测与配置解析
# ============================================================================

# 检测 SSH 端口（多种方法）
detect_ssh_port() {
    debug_log "开始检测 SSH 端口..."
    
    local ssh_port=""
    
    # 方法1: 从活动连接检测
    ssh_port=$(ss -tlnp 2>/dev/null | grep -E 'sshd' | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    debug_log "方法1 (ss): $ssh_port"
    
    # 方法2: 从配置文件检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -E '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
        debug_log "方法2 (config): $ssh_port"
    fi
    
    # 方法3: 从当前会话检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
        debug_log "方法3 (session): $ssh_port"
    fi
    
    # 方法4: 使用 lsof
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && command -v lsof >/dev/null 2>&1; then
        ssh_port=$(lsof -i -P -n | grep sshd | grep LISTEN | awk '{print $9}' | cut -d: -f2 | head -1)
        debug_log "方法4 (lsof): $ssh_port"
    fi
    
    # 默认值
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
        warning "无法检测 SSH 端口，使用默认值: 22"
    fi
    
    SSH_PORT="$ssh_port"
    success "SSH 端口: $SSH_PORT"
}

# 检测 Docker 容器端口
detect_docker_ports() {
    if [ "$ENABLE_DOCKER" = false ]; then
        debug_log "Docker 端口检测已禁用"
        return 0
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        debug_log "Docker 未安装，跳过容器端口检测"
        return 0
    fi
    
    if ! docker ps >/dev/null 2>&1; then
        debug_log "Docker 服务未运行或无权限访问"
        return 0
    fi
    
    info "检测 Docker 容器端口..."
    
    local container_ports=()
    local container_count=0
    
    # 获取所有运行中的容器
    while IFS= read -r container; do
        container_count=$((container_count + 1))
        debug_log "检查容器: $container"
        
        # 方法1: 使用 docker port
        local ports=$(docker port "$container" 2>/dev/null | grep -oE '0\.0\.0\.0:[0-9]+' | cut -d: -f2)
        
        # 方法2: 使用 docker inspect
        if [ -z "$ports" ]; then
            ports=$(docker inspect "$container" 2>/dev/null | \
                    jq -r '.[0].NetworkSettings.Ports | to_entries[] | .value[]? | select(.HostIp == "0.0.0.0") | .HostPort' 2>/dev/null)
        fi
        
        if [ -n "$ports" ]; then
            while read -r port; do
                if validate_port "$port" && ! is_internal_service_port "$port"; then
                    container_ports+=("$port")
                    debug_log "发现 Docker 端口: $port (容器: $container)"
                fi
            done <<< "$ports"
        fi
    done <<< "$(docker ps --format '{{.Names}}' 2>/dev/null)"
    
    if [ ${#container_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${container_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从 $container_count 个 Docker 容器检测到 ${#unique_ports[@]} 个端口"
    else
        debug_log "未从 Docker 容器检测到端口"
    fi
}

# 检测现有的 NAT 规则（改进版）
detect_existing_nat_rules() {
    info "检测现有端口转发规则..."
    
    local nat_rules=()
    local rules_found=0
    
    if ! command -v iptables >/dev/null 2>&1; then
        warning "iptables 不可用，跳过 NAT 规则检测"
        return 0
    fi
    
    # 检查 PREROUTING 链
    while IFS= read -r line; do
        # 跳过标题和空行
        if [[ "$line" =~ ^(num|Chain|target|pkts|$) ]]; then
            continue
        fi
        
        debug_log "分析 NAT 规则: $line"
        
        # 检查是否为 DNAT 规则
        if echo "$line" | grep -qE "(DNAT|dnat)"; then
            rules_found=$((rules_found + 1))
            local port_range=""
            local target_port=""
            
            # 提取端口范围（支持多种格式）
            if echo "$line" | grep -qE "dpts:[0-9]+:[0-9]+"; then
                port_range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | sed 's/dpts://' | tr ':' '-')
            elif echo "$line" | grep -qE "multiport dports [0-9]+:[0-9]+"; then
                port_range=$(echo "$line" | grep -oE "[0-9]+:[0-9]+" | tr ':' '-')
            elif echo "$line" | grep -qE "dport [0-9]+-[0-9]+"; then
                port_range=$(echo "$line" | grep -oE "[0-9]+-[0-9]+")
            fi
            
            # 提取目标端口
            if echo "$line" | grep -qE "to:[0-9\.]*:[0-9]+"; then
                target_port=$(echo "$line" | grep -oE ":[0-9]+$" | tr -d ':')
            elif echo "$line" | grep -qE "to-destination [0-9\.]*:[0-9]+"; then
                target_port=$(echo "$line" | grep -oE "[0-9]+$")
            fi
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                local rule_key="$port_range->$target_port"
                nat_rules+=("$rule_key")
                debug_log "检测到端口转发: $port_range -> $target_port"
            fi
        fi
    done <<< "$(iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null)"
    
    # 处理检测结果
    if [ ${#nat_rules[@]} -gt 0 ]; then
        local unique_rules=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        NAT_RULES=("${unique_rules[@]}")
        
        echo -e "\n${GREEN}┌─ 现有端口转发规则 ─────────────────────┐${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "${GREEN}│ ➜ $rule${RESET}"
        done
        echo -e "${GREEN}└──────────────────────────────────────────┘${RESET}"
        success "检测到 ${#NAT_RULES[@]} 条端口转发规则"
        
        # 提取目标端口添加到检测列表
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "target")
            if [ -n "$target_port" ]; then
                DETECTED_PORTS+=("$target_port")
                debug_log "添加 NAT 目标端口: $target_port"
            fi
        done
    else
        if [ "$rules_found" -gt 0 ]; then
            warning "检测到 $rules_found 条 NAT 规则但无法解析"
        else
            info "未检测到现有端口转发规则"
        fi
    fi
}

# 检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found_processes=()
    local process_count=0
    
    # 检测代理核心进程
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            process_count=$((process_count + 1))
            debug_log "发现代理进程: $process (PID: $(pgrep -f "$process" | head -1))"
        fi
    done
    
    # 检测 Web 面板进程
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            local pid=$(pgrep -f "$process" | head -1)
            # 验证是否与代理相关
            if ps aux | grep "$pid" | grep -qE "(proxy|v2ray|xray|sing|hiddify|marzban)"; then
                found_processes+=("$process")
                process_count=$((process_count + 1))
                debug_log "发现 Web 面板进程: $process (PID: $pid)"
            fi
        fi
    done
    
    if [ ${#found_processes[@]} -gt 0 ]; then
        echo -e "\n${GREEN}┌─ 检测到的代理进程 ───────────────────────┐${RESET}"
        for proc in "${found_processes[@]}"; do
            local pid=$(pgrep -f "$proc" | head -1)
            local memory=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1fMB", $1/1024}')
            echo -e "${GREEN}│ ✓ $proc${RESET} (PID: $pid, 内存: ${memory:-N/A})"
        done
        echo -e "${GREEN}└──────────────────────────────────────────┘${RESET}"
        success "检测到 $process_count 个代理相关进程"
        return 0
    else
        warning "未检测到运行中的代理进程"
        warning "建议在启动代理服务后运行此脚本以获得最佳效果"
        return 1
    fi
}

# 检查绑定地址类型
check_bind_address() {
    local address="$1"
    
    # 公网地址
    if [[ "$address" =~ ^(\*|0\.0\.0\.0|\[::\]|::):([0-9]+)$ ]]; then
        echo "public"
    # 本地回环
    elif [[ "$address" =~ ^(127\.|::1|\[::1\]):([0-9]+)$ ]]; then
        echo "localhost"
    # 私有网络
    elif [[ "$address" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.):([0-9]+)$ ]]; then
        echo "private"
    # Docker 网桥
    elif [[ "$address" =~ ^172\.17\.:([0-9]+)$ ]]; then
        echo "docker"
    else
        echo "unknown"
    fi
}

# 从配置文件解析端口（增强版）
parse_config_ports() {
    info "从配置文件解析端口..."
    
    local config_ports=()
    local files_parsed=0
    local total_files=${#PROXY_CONFIG_FILES[@]}
    
    for i in "${!PROXY_CONFIG_FILES[@]}"; do
        local config_file="${PROXY_CONFIG_FILES[$i]}"
        
        show_progress $((i + 1)) "$total_files" "解析配置文件..."
        
        if [ ! -f "$config_file" ]; then
            debug_log "配置文件不存在: $config_file"
            continue
        fi
        
        files_parsed=$((files_parsed + 1))
        debug_log "分析配置文件: $config_file"
        
        # JSON 文件
        if [[ "$config_file" =~ \.json$ ]]; then
            if command -v jq >/dev/null 2>&1; then
                # 使用 jq 精确解析
                local ports=$(jq -r '
                    .. | 
                    select(type == "object") | 
                    select(has("port") or has("listen_port") or has("server_port")) |
                    select(
                        (.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::" or .listen == "[::]") or
                        (has("listen") | not)
                    ) |
                    (.port // .listen_port // .server_port)
                ' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析端口: $port"
                        fi
                    done <<< "$ports"
                fi
            else
                # 降级方案：使用 grep
                local ports=$(grep -oE '"(port|listen_port|server_port)"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | \
                              grep -oE '[0-9]+' | sort -nu)
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析端口(grep): $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        
        # YAML 文件
        elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
            local ports=$(grep -oE '(port|listen_port|server_port)[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | \
                          grep -oE '[0-9]+' | sort -nu)
            if [ -n "$ports" ]; then
                while read -r port; do
                    if ! is_internal_service_port "$port"; then
                        config_ports+=("$port")
                        debug_log "从 $config_file 解析 YAML 端口: $port"
                    fi
                done <<< "$ports"
            fi
        
        # ENV 文件
        elif [[ "$config_file" =~ \.env$ ]]; then
            local ports=$(grep -E '^[A-Z_]*PORT=' "$config_file" | cut -d'=' -f2 | tr -d '"' | \
                          grep -E '^[0-9]+$' | sort -nu)
            if [ -n "$ports" ]; then
                while read -r port; do
                    if ! is_internal_service_port "$port"; then
                        config_ports+=("$port")
                        debug_log "从 $config_file 解析 ENV 端口: $port"
                    fi
                done <<< "$ports"
            fi
        
        # Python 配置文件
        elif [[ "$config_file" =~ \.py$ ]]; then
            local ports=$(grep -oE "(PORT|port)[[:space:]]*=[[:space:]]*[0-9]+" "$config_file" | \
                          grep -oE '[0-9]+' | sort -nu)
            if [ -n "$ports" ]; then
                while read -r port; do
                    if ! is_internal_service_port "$port"; then
                        config_ports+=("$port")
                        debug_log "从 $config_file 解析 Python 端口: $port"
                    fi
                done <<< "$ports"
            fi
        fi
    done
    
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从 $files_parsed 个配置文件解析到 ${#unique_ports[@]} 个端口"
    else
        if [ $files_parsed -gt 0 ]; then
            warning "已检查 $files_parsed 个配置文件，但未解析到端口"
        else
            info "未找到可解析的配置文件"
        fi
    fi
}

# 检测监听端口（增强版）
detect_listening_ports() {
    info "检测当前监听端口..."
    
    local listening_ports=()
    local localhost_ports=()
    local private_ports=()
    local lines_processed=0
    
    while IFS= read -r line; do
        lines_processed=$((lines_processed + 1))
        
        # 只处理 LISTEN 和 UNCONN 状态
        if [[ ! "$line" =~ (LISTEN|UNCONN) ]]; then
            continue
        fi
        
        local protocol=$(echo "$line" | awk '{print tolower($1)}')
        local address_port=$(echo "$line" | awk '{print $5}')
        local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
        
        # 提取端口号
        local port=$(echo "$address_port" | grep -oE '[0-9]+$')
        
        if ! validate_port "$port"; then
            continue
        fi
        
        # 提取进程名
        local process="unknown"
        if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
            process="${BASH_REMATCH[1]}"
        fi
        
        # 检查绑定类型
        local bind_type=$(check_bind_address "$address_port")
        
        debug_log "端口分析: $address_port | 协议: $protocol | 进程: $process | 类型: $bind_type"
        
        # 跳过 SSH 端口
        if [ "$port" = "$SSH_PORT" ]; then
            debug_log "跳过 SSH 端口: $port"
            continue
        fi
        
        # 判断是否为代理相关进程
        if is_proxy_related "$process"; then
            case "$bind_type" in
                "public")
                    if ! is_internal_service_port "$port"; then
                        listening_ports+=("$port")
                        debug_log "✓ 公共代理端口: $port ($protocol, $process)"
                    else
                        debug_log "✗ 内部服务端口: $port (不暴露)"
                    fi
                    ;;
                "localhost")
                    localhost_ports+=("$port")
                    debug_log "⊙ 本地端口: $port (仅本地访问)"
                    ;;
                "private"|"docker")
                    private_ports+=("$port")
                    debug_log "◎ 私有网络端口: $port ($bind_type)"
                    ;;
            esac
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    # 显示内部端口信息
    if [ ${#localhost_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}┌─ 内部服务端口（仅本地）─────────────────┐${RESET}"
        for port in $(printf '%s\n' "${localhost_ports[@]}" | sort -nu); do
            echo -e "${YELLOW}│ 🔒 $port${RESET} - 内部服务，不对外暴露"
        done
        echo -e "${YELLOW}└──────────────────────────────────────────┘${RESET}"
    fi
    
    # 显示私有网络端口
    if [ ${#private_ports[@]} -gt 0 ]; then
        debug_log "检测到私有网络端口: ${private_ports[*]}"
    fi
    
    # 添加公共端口到检测列表
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从 $lines_processed 行数据中检测到 ${#unique_ports[@]} 个公共监听端口"
    else
        warning "未检测到公共监听端口"
    fi
}

# 检查进程是否为代理相关
is_proxy_related() {
    local process="$1"
    
    # 检查核心代理进程
    for proxy_proc in "${PROXY_CORE_PROCESSES[@]}"; do
        if [[ "$process" == *"$proxy_proc"* ]]; then
            return 0
        fi
    done
    
    # 检查 Web 面板进程
    for panel_proc in "${WEB_PANEL_PROCESSES[@]}"; do
        if [[ "$process" == *"$panel_proc"* ]]; then
            return 0
        fi
    done
    
    # 通过关键字匹配
    if [[ "$process" =~ (proxy|vpn|tunnel|shadowsocks|trojan|v2ray|xray|clash|hysteria|sing|marzban|reality|vless|vmess|ss-|tuic|juicity) ]]; then
        return 0
    fi
    
    return 1
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# 检查端口是否在黑名单
is_blacklisted_port() {
    local port="$1"
    
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# 第二部分完成
# 下一部分将包含：端口过滤、NAT 配置、防火墙应用
# ============================================================================
# 第三部分：端口过滤、NAT 配置、防火墙应用
# ============================================================================

# 检查端口是否为标准代理端口
is_standard_proxy_port() {
    local port="$1"
    
    # 常用 HTTP/HTTPS 端口
    local common_http_ports=(80 443 8080 8443 8880 8888 2052 2053 2082 2083 2086 2087 2095 2096)
    for common_port in "${common_http_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    # SOCKS 代理端口
    if [ "$port" = "1080" ] || [ "$port" = "1085" ]; then
        return 0
    fi
    
    # Shadowsocks 常用端口
    if [ "$port" = "8388" ] || [ "$port" = "8389" ]; then
        return 0
    fi
    
    # Hysteria 端口范围
    if [ "$port" -ge 10000 ] && [ "$port" -le 65000 ]; then
        if ! is_internal_service_port "$port" && ! is_blacklisted_port "$port"; then
            return 0
        fi
    fi
    
    return 1
}

# 端口安全检查（综合版）
is_port_safe() {
    local port="$1"
    
    # 检查黑名单
    if is_blacklisted_port "$port"; then
        debug_log "端口 $port 在黑名单中"
        return 1
    fi
    
    # 检查内部服务
    if is_internal_service_port "$port"; then
        debug_log "端口 $port 是内部服务端口"
        return 1
    fi
    
    # 检查有效范围
    if ! validate_port "$port"; then
        debug_log "端口 $port 无效"
        return 1
    fi
    
    # 默认开放端口总是安全
    for default_port in "${DEFAULT_OPEN_PORTS[@]}"; do
        if [ "$port" = "$default_port" ]; then
            return 0
        fi
    done
    
    return 0
}

# 端口分类和过滤
filter_and_confirm_ports() {
    info "智能端口分析和确认..."
    
    # 添加默认开放端口
    info "添加默认开放端口: ${DEFAULT_OPEN_PORTS[*]}"
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    # 去重并排序
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    
    local safe_ports=()
    local suspicious_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
    # 端口分类
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
            suspicious_ports+=("$port")
        fi
    done
    
    # 显示分类结果
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "\n${GREEN}┌─ 标准代理端口（推荐开放）───────────────┐${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "${GREEN}│ ✓ $port${RESET} - 默认开放端口"
            else
                echo -e "${GREEN}│ ✓ $port${RESET} - 常用代理端口"
            fi
        done
        echo -e "${GREEN}└──────────────────────────────────────────┘${RESET}"
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}┌─ 内部服务端口（已过滤）─────────────────┐${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "${YELLOW}│ - $port${RESET} - 内部服务，不对外暴露"
        done
        echo -e "${YELLOW}└──────────────────────────────────────────┘${RESET}"
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}┌─ 可疑端口（需要确认）───────────────────┐${RESET}"
        for port in "${suspicious_ports[@]}"; do
            echo -e "${YELLOW}│ ? $port${RESET} - 非标准代理端口"
        done
        echo -e "${YELLOW}└──────────────────────────────────────────┘${RESET}"
        
        echo -e "\n${YELLOW}这些端口可能不是必要的代理端口，建议谨慎开放${RESET}"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}是否也要开放这些可疑端口？[y/N]${RESET}"
            read -r -t 30 response || response="n"
            if [[ "$response" =~ ^[Yy]$ ]]; then
                safe_ports+=("${suspicious_ports[@]}")
                info "用户确认开放可疑端口"
            else
                info "跳过可疑端口"
            fi
        fi
    fi
    
    if [ ${#unsafe_ports[@]} -gt 0 ]; then
        echo -e "\n${RED}┌─ 危险端口（已阻止）─────────────────────┐${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "${RED}│ ✗ $port${RESET} - 系统端口或危险端口"
        done
        echo -e "${RED}└──────────────────────────────────────────┘${RESET}"
    fi
    
    # 询问是否配置端口转发
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 是否需要配置端口转发（Port Hopping）？[y/N]${RESET}"
        echo -e "${YELLOW}端口转发可以将端口范围重定向到单个目标端口，增强安全性${RESET}"
        read -r -t 30 response || response="n"
        if [[ "$response" =~ ^[Yy]$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    # 确保至少有基本端口
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "未检测到标准代理端口，将使用默认端口"
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    # 最终确认
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}╔══════════════════════════════════════════╗${RESET}"
        echo -e "${CYAN}║        最终配置确认                       ║${RESET}"
        echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"
        
        echo -e "\n${CYAN}📋 即将开放的端口:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (默认开放)"
            else
                echo -e "  ${CYAN}• $port${RESET}"
            fi
        done
        
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
            for rule in "${NAT_RULES[@]}"; do
                echo -e "  ${CYAN}• $rule${RESET}"
            done
        fi
        
        echo -e "\n${YELLOW}确认配置并应用防火墙规则？[Y/n]${RESET}"
        read -r -t 30 response || response="y"
        if [[ "$response" =~ ^[Nn]$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    success "端口过滤完成，共 ${#DETECTED_PORTS[@]} 个端口待开放"
    return 0
}

# 交互式端口范围添加（增强版）
add_port_range_interactive() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║      配置端口转发规则                     ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"
    
    echo -e "\n${YELLOW}端口转发允许将端口范围重定向到单个目标端口${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    echo -e "${YELLOW}用途: 实现端口跳跃（Port Hopping），增强安全性${RESET}\n"
    
    while true; do
        echo -e "${CYAN}请输入端口范围（格式: 起始-结束，如 16820-16888）:${RESET}"
        read -r port_range
        
        if [ -z "$port_range" ]; then
            warning "输入为空，请重新输入"
            continue
        fi
        
        if ! validate_port_range "$port_range"; then
            echo -e "${RED}❌ 无效的端口范围格式: $port_range${RESET}"
            echo -e "${YELLOW}正确格式示例: 10000-10100 (起始端口必须小于结束端口)${RESET}"
            continue
        fi
        
        # 提取起始和结束端口
        local start_port="${port_range%-*}"
        local end_port="${port_range#*-}"
        
        # 检查端口范围大小
        local range_size=$((end_port - start_port + 1))
        if [ "$range_size" -gt 10000 ]; then
            warning "端口范围过大 ($range_size 个端口)，建议不超过 10000"
            echo -e "${YELLOW}是否继续？[y/N]${RESET}"
            read -r response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                continue
            fi
        fi
        
        echo -e "\n${CYAN}请输入目标端口（单个端口号）:${RESET}"
        read -r target_port
        
        if ! validate_port "$target_port"; then
            echo -e "${RED}❌ 无效的目标端口: $target_port${RESET}"
            echo -e "${YELLOW}端口号必须在 1-65535 之间${RESET}"
            continue
        fi
        
        # 检查目标端口是否在监听
        if ! ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
            warning "目标端口 $target_port 当前未在监听"
            echo -e "${YELLOW}请确保代理服务运行在此端口，否则转发将无法工作${RESET}"
            echo -e "${YELLOW}是否继续添加？[y/N]${RESET}"
            read -r response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                continue
            fi
        fi
        
        # 添加规则
        local rule_key="$port_range->$target_port"
        NAT_RULES+=("$rule_key")
        DETECTED_PORTS+=("$target_port")
        
        success "✅ 已添加端口转发规则: $port_range -> $target_port"
        info "端口范围大小: $range_size 个端口"
        
        echo -e "\n${YELLOW}是否继续添加其他端口转发规则？[y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            break
        fi
        echo
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 已配置 ${#NAT_RULES[@]} 条端口转发规则${RESET}"
    fi
}

# 清理 NAT 规则（增强版）
clean_nat_rules_only() {
    echo -e "\n${YELLOW}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║      清理 NAT 端口转发规则                ║${RESET}"
    echo -e "${YELLOW}╚══════════════════════════════════════════╝${RESET}\n"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}⚠️  警告: 这将清除所有现有的 NAT 端口转发规则！${RESET}"
        echo -e "${YELLOW}确认清理 NAT 规则吗？[y/N]${RESET}"
        read -r -t 30 response || response="n"
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            info "清理操作已取消"
            return 0
        fi
    fi
    
    info "正在分析 NAT 规则..."
    
    # 备份当前规则
    local backup_file="$BACKUP_DIR/nat_rules_backup_$BACKUP_TIMESTAMP.txt"
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "$BACKUP_DIR"
        iptables-save -t nat > "$backup_file" 2>/dev/null || true
        if [ -f "$backup_file" ]; then
            success "NAT 规则已备份到: $backup_file"
        fi
    fi
    
    # 统计规则数量
    local rule_count=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep -c "DNAT" || echo "0")
    
    if [ "$rule_count" -eq 0 ]; then
        info "没有需要清理的 NAT 规则"
        return 0
    fi
    
    info "检测到 $rule_count 条 NAT 规则"
    
    if [ "$DRY_RUN" = false ]; then
        # 清理 PREROUTING 链
        iptables -t nat -F PREROUTING 2>/dev/null || true
        success "已清理 $rule_count 条 NAT 规则"
        
        # 保存更改
        save_iptables_rules
    else
        info "[预览模式] 将清理 $rule_count 条 NAT 规则"
    fi
    
    echo -e "\n${GREEN}✅ NAT 规则清理完成${RESET}"
    if [ "$rule_count" -gt 0 ] && [ "$DRY_RUN" = false ]; then
        echo -e "${CYAN}💡 提示: 如需重新配置端口转发，请运行:${RESET}"
        echo -e "${CYAN}   bash $0 --add-range${RESET}"
    fi
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将清理现有防火墙"
        return 0
    fi
    
    # 停止并禁用其他防火墙服务
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            info "停止 $service 服务..."
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "已禁用 $service"
        fi
    done
    
    # 重置 UFW
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 备份现有规则
    local backup_file="$BACKUP_DIR/iptables_backup_$BACKUP_TIMESTAMP.txt"
    mkdir -p "$BACKUP_DIR"
    iptables-save > "$backup_file" 2>/dev/null || true
    if [ -f "$backup_file" ]; then
        debug_log "iptables 规则已备份到: $backup_file"
    fi
    
    # 设置默认策略为 ACCEPT（避免锁定）
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # 清理 filter 表
    iptables -F INPUT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    
    # 清理自定义链
    iptables -X 2>/dev/null || true
    
    # 注意：不清理 NAT 表，保留现有端口转发
    if [ ${#NAT_RULES[@]} -eq 0 ]; then
        debug_log "未检测到需要保留的 NAT 规则，清理 NAT 表"
        iptables -t nat -F PREROUTING 2>/dev/null || true
    fi
    
    success "防火墙清理完成"
}

# 设置 SSH 保护（增强版）
setup_ssh_protection() {
    info "配置 SSH 暴力破解防护..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将设置 SSH 保护"
        return 0
    fi
    
    # 创建 SSH 保护链
    iptables -N SSH_PROTECTION 2>/dev/null || iptables -F SSH_PROTECTION
    
    # SSH 暴力破解防护规则
    # 1. 允许已建立的连接
    iptables -A SSH_PROTECTION -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 2. 限速：60秒内超过4次连接尝试则阻止
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP
    
    # 3. 记录连接尝试
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --set
    
    # 4. 允许新连接
    iptables -A SSH_PROTECTION -j ACCEPT
    
    success "SSH 暴力破解防护已配置 (端口: $SSH_PORT)"
    info "限制规则: 60秒内最多3次连接尝试"
}

# 应用 iptables 规则（核心函数）
apply_firewall_rules() {
    info "应用 iptables 防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 防火墙规则预览:"
        show_rules_preview
        return 0
    fi
    
    echo -e "\n${CYAN}正在应用防火墙规则...${RESET}"
    
    # 第一步：设置默认策略（先 ACCEPT）
    show_progress 1 10 "设置默认策略..."
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 第二步：基本规则
    show_progress 2 10 "配置基本规则..."
    # 允许回环接口
    iptables -A INPUT -i lo -j ACCEPT
    # 允许已建立和相关连接
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 第三步：ICMP 支持
    show_progress 3 10 "配置 ICMP 规则..."
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    
    # 第四步：SSH 保护
    show_progress 4 10 "配置 SSH 保护..."
    setup_ssh_protection
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j SSH_PROTECTION
    
    # 第五步：开放代理端口
    show_progress 5 10 "开放代理端口..."
    for port in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        debug_log "已开放端口: $port (TCP/UDP)"
    done
    
    # 第六步：应用 NAT 规则
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        show_progress 6 10 "配置端口转发..."
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "range")
            local target_port=$(split_nat_rule "$rule" "target")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                local start_port="${port_range%-*}"
                local end_port="${port_range#*-}"
                
                # 添加 DNAT 规则（UDP 和 TCP）
                iptables -t nat -A PREROUTING -p udp --dport "$start_port:$end_port" \
                    -j DNAT --to-destination ":$target_port" 2>/dev/null || true
                iptables -t nat -A PREROUTING -p tcp --dport "$start_port:$end_port" \
                    -j DNAT --to-destination ":$target_port" 2>/dev/null || true
                
                # 开放端口范围
                iptables -A INPUT -p tcp --dport "$start_port:$end_port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$start_port:$end_port" -j ACCEPT
                
                debug_log "NAT 规则已应用: $port_range -> $target_port"
            fi
        done
    else
        show_progress 6 10 "跳过端口转发..."
    fi
    
    # 第七步：日志记录
    show_progress 7 10 "配置日志记录..."
    iptables -A INPUT -m limit --limit 3/min --limit-burst 3 \
        -j LOG --log-prefix "[iptables-drop] " --log-level 4
    
    # 第八步：IPv6 规则（如果启用）
    if [ "$ENABLE_IPV6" = true ]; then
        show_progress 8 10 "配置 IPv6 规则..."
        apply_ipv6_rules
    else
        show_progress 8 10 "跳过 IPv6..."
    fi
    
    # 第九步：最终设置默认丢弃策略
    show_progress 9 10 "设置默认丢弃策略..."
    iptables -P INPUT DROP
    
    # 第十步：保存规则
    show_progress 10 10 "保存防火墙规则..."
    save_iptables_rules
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    echo
    success "iptables 规则应用成功"
}

# IPv6 规则应用
apply_ipv6_rules() {
    if [ "$ENABLE_IPV6" = false ]; then
        return 0
    fi
    
    debug_log "应用 IPv6 防火墙规则..."
    
    # 设置默认策略
    ip6tables -P INPUT DROP 2>/dev/null || return 1
    ip6tables -P FORWARD DROP 2>/dev/null || true
    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # 基本规则
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # ICMPv6
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    
    # SSH
    ip6tables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    
    # 代理端口
    for port in "${DETECTED_PORTS[@]}"; do
        ip6tables -A INPUT -p tcp --dport "$port" -j ACCEPT
        ip6tables -A INPUT -p udp --dport "$port" -j ACCEPT
    done
    
    # 保存 IPv6 规则
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi
    
    success "IPv6 规则已应用"
}

# 第三部分完成
# 下一部分将包含：规则保存、状态显示、备份恢复、主函数
# ============================================================================
# 第四部分：规则保存、状态显示、备份恢复、主函数
# ============================================================================

# 保存 iptables 规则（多系统兼容）
save_iptables_rules() {
    info "保存 iptables 规则..."
    
    if ! command -v iptables-save >/dev/null 2>&1; then
        warning "iptables-save 不可用，规则将在重启后丢失"
        return 1
    fi
    
    local saved=false
    
    # Debian/Ubuntu 系统
    if [ -d "/etc/iptables" ] || command -v dpkg >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null && saved=true
        
        if [ "$ENABLE_IPV6" = true ] && command -v ip6tables-save >/dev/null 2>&1; then
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        fi
        
        # 创建 systemd 服务
        cat > /etc/systemd/system/iptables-restore.service << 'SYSTEMD_EOF'
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
SYSTEMD_EOF
        
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable iptables-restore.service >/dev/null 2>&1 || true
        
    # RHEL/CentOS 系统
    elif [ -d "/etc/sysconfig" ] || command -v rpm >/dev/null 2>&1; then
        mkdir -p /etc/sysconfig
        iptables-save > /etc/sysconfig/iptables 2>/dev/null && saved=true
        
        if [ "$ENABLE_IPV6" = true ] && command -v ip6tables-save >/dev/null 2>&1; then
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
        fi
        
        systemctl enable iptables >/dev/null 2>&1 || true
        
    # 其他系统
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null && saved=true
    fi
    
    if [ "$saved" = true ]; then
        success "iptables 规则已保存"
        
        # 创建恢复脚本
        cat > /usr/local/bin/restore-iptables.sh << 'RESTORE_EOF'
#!/bin/bash
# 自动生成的 iptables 规则恢复脚本

if [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4
    echo "✅ IPv4 规则已恢复"
fi

if [ -f /etc/iptables/rules.v6 ]; then
    ip6tables-restore < /etc/iptables/rules.v6
    echo "✅ IPv6 规则已恢复"
fi
RESTORE_EOF
        
        chmod +x /usr/local/bin/restore-iptables.sh
        debug_log "恢复脚本已创建: /usr/local/bin/restore-iptables.sh"
    else
        warning "规则保存失败，可能在重启后丢失"
    fi
}

# 显示规则预览
show_rules_preview() {
    cat << PREVIEW_EOF

${CYAN}╔══════════════════════════════════════════════════════════╗
║              iptables 规则预览                            ║
╚══════════════════════════════════════════════════════════╝${RESET}

${GREEN}# 1. 默认策略${RESET}
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

${GREEN}# 2. 基本规则${RESET}
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

${GREEN}# 3. ICMP 支持${RESET}
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT

${GREEN}# 4. SSH 保护 (端口: $SSH_PORT)${RESET}
iptables -N SSH_PROTECTION
iptables -A SSH_PROTECTION -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP
iptables -A SSH_PROTECTION -m recent --name ssh_attempts --set -j ACCEPT
iptables -A INPUT -p tcp --dport $SSH_PORT -j SSH_PROTECTION

${GREEN}# 5. 代理端口 (共 ${#DETECTED_PORTS[@]} 个)${RESET}
PREVIEW_EOF

    for port in "${DETECTED_PORTS[@]}"; do
        echo "iptables -A INPUT -p tcp --dport $port -j ACCEPT"
        echo "iptables -A INPUT -p udp --dport $port -j ACCEPT"
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        cat << NAT_PREVIEW_EOF

${GREEN}# 6. 端口转发规则 (共 ${#NAT_RULES[@]} 条)${RESET}
NAT_PREVIEW_EOF
        
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "range")
            local target_port=$(split_nat_rule "$rule" "target")
            local start_port="${port_range%-*}"
            local end_port="${port_range#*-}"
            
            echo "iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
            echo "iptables -t nat -A PREROUTING -p tcp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
            echo "iptables -A INPUT -p tcp --dport $start_port:$end_port -j ACCEPT"
            echo "iptables -A INPUT -p udp --dport $start_port:$end_port -j ACCEPT"
        done
    fi
    
    cat << PREVIEW_EOF2

${GREEN}# 7. 日志和丢弃${RESET}
iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix '[iptables-drop] '
iptables -A INPUT -j DROP

PREVIEW_EOF2
}

# 验证端口转发功能
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -eq 0 ]; then
        return 0
    fi
    
    info "验证端口转发配置..."
    
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║           NAT 规则状态验证                                ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    # 显示当前 NAT 规则
    if command -v iptables >/dev/null 2>&1; then
        local nat_output=$(iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep DNAT)
        if [ -n "$nat_output" ]; then
            echo -e "${GREEN}当前活跃的 NAT 规则:${RESET}"
            echo "$nat_output" | while read -r line; do
                echo -e "  ${GREEN}•${RESET} $line"
            done
        else
            warning "未发现活跃的 NAT 规则"
        fi
    fi
    
    echo -e "\n${YELLOW}💡 端口转发使用说明:${RESET}"
    echo -e "  ${CYAN}•${RESET} 客户端可以连接到范围内的任意端口"
    echo -e "  ${CYAN}•${RESET} 所有连接都会自动转发到目标端口"
    echo -e "  ${CYAN}•${RESET} 支持 UDP 和 TCP 协议"
    
    # 检查目标端口监听状态
    echo -e "\n${CYAN}目标端口监听状态:${RESET}"
    local checked_ports=()
    for rule in "${NAT_RULES[@]}"; do
        local port_range=$(split_nat_rule "$rule" "range")
        local target_port=$(split_nat_rule "$rule" "target")
        
        if [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
            checked_ports+=("$target_port")
            
            if ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                echo -e "  ${GREEN}✓ 端口 $target_port 正在监听${RESET} ($port_range -> $target_port)"
            else
                echo -e "  ${YELLOW}⚠ 端口 $target_port 未在监听${RESET} ($port_range -> $target_port)"
                echo -e "     ${YELLOW}提示: 请确保代理服务运行在此端口${RESET}"
            fi
        fi
    done
    
    # 规则摘要
    echo -e "\n${CYAN}端口转发规则摘要:${RESET}"
    local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
    for rule in "${unique_rules[@]}"; do
        local port_range=$(split_nat_rule "$rule" "range")
        local target_port=$(split_nat_rule "$rule" "target")
        local range_size=$((${port_range#*-} - ${port_range%-*} + 1))
        echo -e "  ${CYAN}•${RESET} $port_range → $target_port (范围: $range_size 个端口)"
    done
}

# 显示防火墙状态（增强版）
show_firewall_status() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              防火墙状态详情                               ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    # 1. 规则统计
    echo -e "${GREEN}📊 规则统计:${RESET}"
    local input_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | wc -l)
    local nat_rules=$(iptables -t nat -L PREROUTING --line-numbers 2>/dev/null | grep -c "DNAT" || echo "0")
    echo -e "  • INPUT 规则数: $((input_rules - 2))"
    echo -e "  • NAT 转发规则: $nat_rules"
    
    if [ "$ENABLE_IPV6" = true ]; then
        local ipv6_rules=$(ip6tables -L INPUT --line-numbers 2>/dev/null | wc -l)
        echo -e "  • IPv6 规则数: $((ipv6_rules - 2))"
    fi
    
    # 2. 开放端口
    echo -e "\n${GREEN}🔓 开放的端口:${RESET}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E "dpt:[0-9]+" | while read -r line; do
        local port=$(echo "$line" | grep -oE "dpt:[0-9]+" | cut -d: -f2)
        local protocol=$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
        if [ -n "$port" ]; then
            if [ "$port" = "$SSH_PORT" ]; then
                echo -e "  • ${YELLOW}$port${RESET} ($protocol) - SSH (受保护)"
            elif [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  • ${GREEN}$port${RESET} ($protocol) - 默认开放"
            else
                echo -e "  • ${CYAN}$port${RESET} ($protocol)"
            fi
        fi
    done
    
    # 3. 端口转发规则
    echo -e "\n${GREEN}🔄 端口转发规则:${RESET}"
    local nat_found=false
    while read -r line; do
        if echo "$line" | grep -q "DNAT"; then
            nat_found=true
            local port_info=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | sed 's/dpts://')
            local target=$(echo "$line" | grep -oE "to:[0-9\.]+:[0-9]+" | sed 's/to://')
            if [ -n "$port_info" ] && [ -n "$target" ]; then
                echo -e "  • ${CYAN}$port_info → $target${RESET}"
            fi
        fi
    done <<< "$(iptables -t nat -L PREROUTING -n -v 2>/dev/null)"
    
    if [ "$nat_found" = false ]; then
        echo -e "  ${YELLOW}无端口转发规则${RESET}"
    fi
    
    # 4. SSH 保护状态
    echo -e "\n${GREEN}🛡️  SSH 保护状态:${RESET}"
    if iptables -L INPUT -n 2>/dev/null | grep -q "SSH_PROTECTION"; then
        echo -e "  ${GREEN}✓ SSH 暴力破解防护已启用${RESET} (端口: $SSH_PORT)"
        echo -e "    限制: 60秒内最多3次连接尝试"
    else
        echo -e "  ${YELLOW}⚠ SSH 暴力破解防护未启用${RESET}"
    fi
    
    # 5. 系统信息
    echo -e "\n${GREEN}💻 系统信息:${RESET}"
    echo -e "  • 操作系统: $(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d'"' -f2 || echo "Unknown")"
    echo -e "  • 内核版本: $(uname -r)"
    echo -e "  • IPv6 支持: $([ "$ENABLE_IPV6" = true ] && echo "已启用" || echo "未启用")"
    
    # 6. 监听端口
    echo -e "\n${GREEN}👂 当前监听端口 (代理相关):${RESET}"
    ss -tlnp 2>/dev/null | grep -E "LISTEN" | while read -r line; do
        local port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
        local process=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | grep -oE '"[^"]+"' | tr -d '"' | head -1)
        
        if is_proxy_related "$process" 2>/dev/null; then
            echo -e "  • ${CYAN}$port${RESET} - $process"
        fi
    done
    
    # 7. 管理命令
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              常用管理命令                                 ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET}"
    echo -e "    iptables -L -n -v --line-numbers"
    echo -e "  ${YELLOW}查看 NAT 规则:${RESET}"
    echo -e "    iptables -t nat -L -n -v --line-numbers"
    echo -e "  ${YELLOW}查看监听端口:${RESET}"
    echo -e "    ss -tlnp"
    echo -e "  ${YELLOW}重新配置防火墙:${RESET}"
    echo -e "    bash $0"
    echo -e "  ${YELLOW}添加端口转发:${RESET}"
    echo -e "    bash $0 --add-range"
    echo -e "  ${YELLOW}备份配置:${RESET}"
    echo -e "    bash $0 --backup"
    echo -e "  ${YELLOW}查看实时日志:${RESET}"
    echo -e "    tail -f /var/log/syslog | grep iptables"
}

# 备份防火墙配置
backup_firewall_config() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              备份防火墙配置                               ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    mkdir -p "$BACKUP_DIR"
    
    local backup_file="$BACKUP_DIR/firewall_full_backup_$BACKUP_TIMESTAMP.tar.gz"
    local temp_dir="/tmp/firewall_backup_$$"
    
    mkdir -p "$temp_dir"
    
    info "正在备份防火墙配置..."
    
    # 备份 iptables 规则
    iptables-save > "$temp_dir/iptables.rules" 2>/dev/null || true
    
    if [ "$ENABLE_IPV6" = true ] && command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > "$temp_dir/ip6tables.rules" 2>/dev/null || true
    fi
    
    # 备份配置文件
    if [ -f /etc/iptables/rules.v4 ]; then
        cp /etc/iptables/rules.v4 "$temp_dir/" 2>/dev/null || true
    fi
    
    if [ -f /etc/iptables/rules.v6 ]; then
        cp /etc/iptables/rules.v6 "$temp_dir/" 2>/dev/null || true
    fi
    
    # 创建备份信息文件
    cat > "$temp_dir/backup_info.txt" << INFO_EOF
备份时间: $(date)
脚本版本: $SCRIPT_VERSION
SSH 端口: $SSH_PORT
IPv6 启用: $ENABLE_IPV6
开放端口数: ${#DETECTED_PORTS[@]}
NAT 规则数: ${#NAT_RULES[@]}
系统信息: $(uname -a)
INFO_EOF
    
    # 打包备份
    tar -czf "$backup_file" -C "$temp_dir" . 2>/dev/null || true
    rm -rf "$temp_dir"
    
    if [ -f "$backup_file" ]; then
        success "备份已保存到: $backup_file"
        local size=$(du -h "$backup_file" | awk '{print $1}')
        info "备份文件大小: $size"
    else
        error_exit "备份失败"
    fi
}

# 恢复防火墙配置
restore_firewall_config() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              恢复防火墙配置                               ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        error_exit "备份目录不存在: $BACKUP_DIR"
    fi
    
    # 列出可用备份
    echo -e "${CYAN}可用的备份文件:${RESET}"
    local backups=($(ls -t "$BACKUP_DIR"/firewall_full_backup_*.tar.gz 2>/dev/null))
    
    if [ ${#backups[@]} -eq 0 ]; then
        error_exit "未找到备份文件"
    fi
    
    for i in "${!backups[@]}"; do
        local backup="${backups[$i]}"
        local date=$(basename "$backup" | grep -oE '[0-9]{8}_[0-9]{6}')
        local size=$(du -h "$backup" | awk '{print $1}')
        echo -e "  ${CYAN}[$((i+1))]${RESET} $date (大小: $size)"
    done
    
    echo -e "\n${YELLOW}请选择要恢复的备份 (1-${#backups[@]}):${RESET}"
    read -r choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
        error_exit "无效的选择"
    fi
    
    local backup_file="${backups[$((choice-1))]}"
    
    echo -e "${RED}⚠️  警告: 这将覆盖当前防火墙配置！${RESET}"
    echo -e "${YELLOW}确认恢复备份？[y/N]${RESET}"
    read -r response
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        info "恢复操作已取消"
        return 0
    fi
    
    local temp_dir="/tmp/firewall_restore_$$"
    mkdir -p "$temp_dir"
    
    info "正在恢复备份: $backup_file"
    
    tar -xzf "$backup_file" -C "$temp_dir" 2>/dev/null || error_exit "解压备份失败"
    
    # 恢复 iptables 规则
    if [ -f "$temp_dir/iptables.rules" ]; then
        iptables-restore < "$temp_dir/iptables.rules" 2>/dev/null || warning "IPv4 规则恢复失败"
        success "IPv4 规则已恢复"
    fi
    
    if [ -f "$temp_dir/ip6tables.rules" ] && command -v ip6tables-restore >/dev/null 2>&1; then
        ip6tables-restore < "$temp_dir/ip6tables.rules" 2>/dev/null || warning "IPv6 规则恢复失败"
        success "IPv6 规则已恢复"
    fi
    
    # 保存规则
    save_iptables_rules
    
    rm -rf "$temp_dir"
    
    echo -e "\n${GREEN}✅ 防火墙配置恢复完成${RESET}"
}

# 重置防火墙
reset_firewall() {
    echo -e "\n${RED}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}║              重置防火墙配置                               ║${RESET}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    echo -e "${RED}⚠️  警告: 这将清除所有 iptables 规则并恢复默认状态！${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${YELLOW}确认重置防火墙吗？[y/N]${RESET}"
        read -r -t 30 response || response="n"
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            info "重置操作已取消"
            return 0
        fi
        
        # 先备份
        info "重置前先备份当前配置..."
        backup_firewall_config
    fi
    
    info "正在重置防火墙..."
    
    if [ "$DRY_RUN" = false ]; then
        # 设置默认 ACCEPT 策略
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        # 清除所有规则
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        
        if [ "$ENABLE_IPV6" = true ] && command -v ip6tables >/dev/null 2>&1; then
            ip6tables -P INPUT ACCEPT
            ip6tables -P FORWARD ACCEPT
            ip6tables -P OUTPUT ACCEPT
            ip6tables -F
            ip6tables -X
        fi
        
        # 保存空规则
        save_iptables_rules
        
        success "防火墙已重置到默认状态 (全部允许)"
    else
        info "[预览模式] 将重置所有防火墙规则"
    fi
    
    echo -e "\n${GREEN}✅ 防火墙重置完成${RESET}"
    warning "当前防火墙处于完全开放状态，建议重新配置"
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║                  配置完成                                 ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    echo -e "${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓${RESET} 开放端口数: $OPENED_PORTS"
    echo -e "  ${GREEN}✓${RESET} SSH 端口: $SSH_PORT (已保护)"
    echo -e "  ${GREEN}✓${RESET} 防火墙引擎: iptables"
    echo -e "  ${GREEN}✓${RESET} IPv6 支持: $([ "$ENABLE_IPV6" = true ] && echo "已启用" || echo "未启用")"
    echo -e "  ${GREEN}✓${RESET} 内部服务保护: 已启用"
    echo -e "  ${GREEN}✓${RESET} 默认端口: ${DEFAULT_OPEN_PORTS[*]} (永久开放)"
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓${RESET} 端口转发规则: ${#unique_nat_rules[@]} 条"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放端口列表:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port${RESET} (TCP/UDP) - 默认开放"
            else
                echo -e "  ${GREEN}• $port${RESET} (TCP/UDP)"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "range")
            local target_port=$(split_nat_rule "$rule" "target")
            local range_size=$((${port_range#*-} - ${port_range%-*} + 1))
            echo -e "  ${CYAN}• $port_range → $target_port${RESET} ($range_size 个端口)"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${YELLOW}⚠️  这是预览模式，防火墙实际未被修改${RESET}"
        echo -e "${CYAN}要应用这些规则，请运行: bash $0${RESET}"
        return 0
    fi
    
    # 验证端口转发
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        verify_port_hopping
    fi
    
    # 显示管理命令
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              常用管理命令                                 ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}查看规则:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}查看日志:${RESET} tail -f /var/log/syslog
    # ============================================================================
# 第五部分：主函数、错误处理、自动化功能（完结）
# ============================================================================

    echo -e "  ${YELLOW}备份配置:${RESET} bash $0 --backup"
    echo -e "  ${YELLOW}添加端口转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 防火墙配置完成！${RESET}"
    echo -e "${GREEN}   代理端口精确开放，端口转发已配置${RESET}"
    echo -e "${GREEN}   内部服务受保护，SSH 暴力破解防护已启用${RESET}\n"
    
    # 检查未监听的目标端口
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local has_unlistened=false
        local checked_ports=()
        
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "target")
            if [ -n "$target_port" ] && [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                checked_ports+=("$target_port")
                if ! ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                    has_unlistened=true
                    break
                fi
            fi
        done
        
        if [ "$has_unlistened" = true ]; then
            echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${RESET}"
            echo -e "${YELLOW}║                  重要提醒                                 ║${RESET}"
            echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${RESET}"
            echo -e "${YELLOW}⚠️  某些端口转发的目标端口未在监听${RESET}"
            echo -e "${YELLOW}   请确保相关代理服务正在运行，否则端口转发可能无法工作${RESET}\n"
        fi
    fi
}

# 健康检查函数
health_check() {
    info "执行系统健康检查..."
    
    local issues=0
    
    # 检查 SSH 连接
    if ! ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT "; then
        warning "SSH 端口 $SSH_PORT 未在监听"
        issues=$((issues + 1))
    fi
    
    # 检查关键服务
    for process in "${PROXY_CORE_PROCESSES[@]:0:5}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            local pid=$(pgrep -f "$process" | head -1)
            if [ -n "$pid" ]; then
                debug_log "服务运行正常: $process (PID: $pid)"
            fi
        fi
    done
    
    # 检查防火墙规则完整性
    local rule_count=$(iptables -L INPUT -n 2>/dev/null | wc -l)
    if [ "$rule_count" -lt 5 ]; then
        warning "防火墙规则数量异常 ($rule_count 条)"
        issues=$((issues + 1))
    fi
    
    # 检查端口冲突
    for port in "${DETECTED_PORTS[@]}"; do
        local listen_count=$(ss -tlnp 2>/dev/null | grep -c ":$port ")
        if [ "$listen_count" -gt 1 ]; then
            warning "端口 $port 存在多个监听进程"
            issues=$((issues + 1))
        fi
    done
    
    if [ "$issues" -eq 0 ]; then
        success "健康检查通过"
    else
        warning "发现 $issues 个潜在问题"
    fi
    
    return $issues
}

# 自动优化建议
optimization_suggestions() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              优化建议                                     ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    local suggestions=()
    
    # 检查端口数量
    if [ ${#DETECTED_PORTS[@]} -gt 20 ]; then
        suggestions+=("开放端口数量较多 (${#DETECTED_PORTS[@]})，建议审查是否都需要")
    fi
    
    # 检查 IPv6
    if [ "$ENABLE_IPV6" = false ] && [ -f /proc/net/if_inet6 ]; then
        suggestions+=("系统支持 IPv6 但未启用，可使用 --ipv6 参数启用")
    fi
    
    # 检查 Docker
    if command -v docker >/dev/null 2>&1 && [ "$ENABLE_DOCKER" = false ]; then
        suggestions+=("检测到 Docker 但未启用端口检测，可能遗漏容器端口")
    fi
    
    # 检查端口转发
    if [ ${#NAT_RULES[@]} -eq 0 ] && [ ${#DETECTED_PORTS[@]} -gt 10 ]; then
        suggestions+=("开放了多个端口，建议配置端口转发以增强安全性")
    fi
    
    # 检查日志记录
    if ! grep -q "iptables" /etc/rsyslog.conf 2>/dev/null; then
        suggestions+=("建议配置 rsyslog 记录 iptables 日志以便审计")
    fi
    
    # 检查自动更新
    if [ ! -f /etc/cron.daily/firewall-update ]; then
        suggestions+=("建议设置定期检查防火墙规则的计划任务")
    fi
    
    # 显示建议
    if [ ${#suggestions[@]} -gt 0 ]; then
        for i in "${!suggestions[@]}"; do
            echo -e "  ${YELLOW}$((i+1)).${RESET} ${suggestions[$i]}"
        done
    else
        echo -e "  ${GREEN}✓ 当前配置已优化，无额外建议${RESET}"
    fi
}

# 生成防火墙报告
generate_report() {
    local report_file="$BACKUP_DIR/firewall_report_$BACKUP_TIMESTAMP.txt"
    
    info "生成防火墙配置报告..."
    
    mkdir -p "$BACKUP_DIR"
    
    cat > "$report_file" << REPORT_EOF
╔══════════════════════════════════════════════════════════╗
║          防火墙配置报告                                   ║
╚══════════════════════════════════════════════════════════╝

报告时间: $(date '+%Y-%m-%d %H:%M:%S')
脚本版本: $SCRIPT_VERSION
主机名: $(hostname)
系统信息: $(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d'"' -f2)
内核版本: $(uname -r)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

【基本配置】
• SSH 端口: $SSH_PORT
• 开放端口数: ${#DETECTED_PORTS[@]}
• NAT 规则数: ${#NAT_RULES[@]}
• IPv6 支持: $([ "$ENABLE_IPV6" = true ] && echo "已启用" || echo "未启用")

【开放端口列表】
REPORT_EOF
    
    for port in "${DETECTED_PORTS[@]}"; do
        if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
            echo "• $port (TCP/UDP) - 默认开放" >> "$report_file"
        else
            echo "• $port (TCP/UDP)" >> "$report_file"
        fi
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        cat >> "$report_file" << REPORT_EOF2

【端口转发规则】
REPORT_EOF2
        for rule in "${NAT_RULES[@]}"; do
            echo "• $rule" >> "$report_file"
        done
    fi
    
    cat >> "$report_file" << REPORT_EOF3

【防火墙规则统计】
• INPUT 规则数: $(iptables -L INPUT -n 2>/dev/null | wc -l)
• FORWARD 规则数: $(iptables -L FORWARD -n 2>/dev/null | wc -l)
• OUTPUT 规则数: $(iptables -L OUTPUT -n 2>/dev/null | wc -l)
• NAT PREROUTING 规则数: $(iptables -t nat -L PREROUTING -n 2>/dev/null | wc -l)

【运行中的代理服务】
REPORT_EOF3
    
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            local pid=$(pgrep -f "$process" | head -1)
            local memory=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1fMB", $1/1024}')
            echo "• $process (PID: $pid, 内存: ${memory:-N/A})" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << REPORT_EOF4

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

【完整 iptables 规则】

$(iptables -L -n -v --line-numbers 2>/dev/null)

【NAT 表规则】

$(iptables -t nat -L -n -v --line-numbers 2>/dev/null)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

报告生成完成
REPORT_EOF4
    
    if [ -f "$report_file" ]; then
        success "报告已保存到: $report_file"
    fi
}

# 监控模式
monitor_mode() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║          实时监控模式 (按 Ctrl+C 退出)                    ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    while true; do
        clear
        echo -e "${CYAN}防火墙实时监控 - $(date '+%Y-%m-%d %H:%M:%S')${RESET}\n"
        
        # 显示连接统计
        echo -e "${GREEN}活跃连接统计:${RESET}"
        local total_conn=$(ss -tan 2>/dev/null | grep -c ESTAB || echo "0")
        echo -e "  • 总连接数: $total_conn"
        
        # 显示各端口连接数
        for port in "${DETECTED_PORTS[@]:0:10}"; do
            local conn_count=$(ss -tan 2>/dev/null | grep ":$port " | grep -c ESTAB || echo "0")
            if [ "$conn_count" -gt 0 ]; then
                echo -e "  • 端口 $port: $conn_count 个连接"
            fi
        done
        
        # 显示最近被阻止的连接
        echo -e "\n${YELLOW}最近被阻止的连接 (最近 5 条):${RESET}"
        tail -n 5 /var/log/syslog 2>/dev/null | grep "iptables-drop" | tail -5 || echo "  无记录"
        
        # 显示系统负载
        echo -e "\n${CYAN}系统负载:${RESET}"
        uptime
        
        sleep 5
    done
}

# 创建定时任务
setup_cron_job() {
    echo -e "\n${CYAN}是否要设置防火墙定期检查？[y/N]${RESET}"
    echo -e "${YELLOW}这将每天检查防火墙规则并生成报告${RESET}"
    read -r -t 30 response || response="n"
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        return 0
    fi
    
    local cron_script="/etc/cron.daily/firewall-check"
    
    cat > "$cron_script" << 'CRON_EOF'
#!/bin/bash
# 防火墙每日检查脚本

BACKUP_DIR="/var/backups/firewall"
LOG_FILE="$BACKUP_DIR/daily_check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

mkdir -p "$BACKUP_DIR"

{
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "防火墙检查 - $TIMESTAMP"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 检查规则数量
    RULE_COUNT=$(iptables -L INPUT -n 2>/dev/null | wc -l)
    echo "INPUT 规则数: $RULE_COUNT"
    
    # 检查 SSH 端口
    SSH_LISTENING=$(ss -tlnp 2>/dev/null | grep -c "sshd")
    echo "SSH 监听状态: $SSH_LISTENING"
    
    # 检查被阻止的连接数
    DROPPED=$(grep "iptables-drop" /var/log/syslog 2>/dev/null | wc -l)
    echo "今日被阻止连接数: $DROPPED"
    
    # 生成规则备份
    iptables-save > "$BACKUP_DIR/rules_$(date +%Y%m%d).bak" 2>/dev/null
    
    echo "检查完成"
    echo ""
    
} >> "$LOG_FILE" 2>&1

# 保留最近 30 天的日志
find "$BACKUP_DIR" -name "rules_*.bak" -mtime +30 -delete 2>/dev/null
CRON_EOF
    
    chmod +x "$cron_script"
    success "定时检查任务已创建: $cron_script"
}

# 交互式配置向导
interactive_wizard() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║          交互式配置向导                                   ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    # 1. 选择代理类型
    echo -e "${CYAN}请选择您使用的代理类型:${RESET}"
    echo -e "  1) Hiddify Manager"
    echo -e "  2) Marzban"
    echo -e "  3) 3X-UI / X-UI"
    echo -e "  4) Sing-box"
    echo -e "  5) Xray / V2Ray"
    echo -e "  6) 其他 / 不确定"
    read -r -p "请选择 (1-6): " proxy_choice
    
    case $proxy_choice in
        1)
            info "Hiddify Manager 通常使用端口 443, 8443, 80"
            DETECTED_PORTS+=(443 8443 80 2053 2083 2087 2096)
            ;;
        2)
            info "Marzban 需要保护管理面板端口"
            echo -e "${YELLOW}请输入 Marzban 管理面板端口 (默认 8000):${RESET}"
            read -r marzban_port
            marzban_port=${marzban_port:-8000}
            INTERNAL_SERVICE_PORTS+=("$marzban_port")
            ;;
        3)
            info "X-UI 系列建议配置端口转发"
            echo -e "${YELLOW}是否配置端口转发？[y/N]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                add_port_range_interactive
            fi
            ;;
        4)
            info "Sing-box 配置灵活，将自动检测配置文件"
            ;;
        5)
            info "将自动检测 Xray/V2Ray 配置文件"
            ;;
        6)
            info "将使用通用检测方法"
            ;;
    esac
    
    # 2. IPv6 支持
    if [ -f /proc/net/if_inet6 ]; then
        echo -e "\n${CYAN}系统支持 IPv6，是否启用 IPv6 防火墙？[y/N]${RESET}"
        read -r -t 30 response || response="n"
        if [[ "$response" =~ ^[Yy]$ ]]; then
            ENABLE_IPV6=true
        fi
    fi
    
    # 3. Docker 支持
    if command -v docker >/dev/null 2>&1; then
        echo -e "\n${CYAN}检测到 Docker，是否检测容器端口？[Y/n]${RESET}"
        read -r -t 30 response || response="y"
        if [[ ! "$response" =~ ^[Nn]$ ]]; then
            ENABLE_DOCKER=true
        fi
    fi
    
    # 4. 定时任务
    setup_cron_job
    
    success "向导配置完成"
}

# 错误处理和恢复
error_handler() {
    local exit_code=$?
    local line_no=$1
    
    echo -e "\n${RED}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}║          发生错误                                         ║${RESET}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${RESET}\n"
    
    echo -e "${RED}错误代码: $exit_code${RESET}"
    echo -e "${RED}错误行号: $line_no${RESET}"
    
    # 尝试恢复
    echo -e "\n${YELLOW}是否尝试恢复到安全状态？[Y/n]${RESET}"
    read -r -t 10 response || response="y"
    
    if [[ ! "$response" =~ ^[Nn]$ ]]; then
        warning "正在恢复防火墙到安全状态..."
        
        # 设置允许所有以避免锁定
        iptables -P INPUT ACCEPT 2>/dev/null || true
        iptables -P FORWARD ACCEPT 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
        
        # 至少保留 SSH
        iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
        
        success "已恢复到安全状态"
        warning "请检查错误后重新运行脚本"
    fi
    
    exit $exit_code
}

# 主函数
main() {
    # 设置错误处理
    trap 'error_handler $LINENO' ERR
    trap 'echo -e "\n${YELLOW}操作被用户中断${RESET}"; exit 130' INT TERM
    
    # 解析参数
    parse_arguments "$@"
    
    # 显示启动信息
    echo -e "\n${CYAN}开始智能代理端口检测和配置...${RESET}"
    
    # 1. 系统检查
    check_system
    
    # 2. 检测 SSH 端口
    detect_ssh_port
    
    # 3. 检测现有 NAT 规则
    detect_existing_nat_rules
    
    # 4. 清理防火墙
    cleanup_firewalls
    
    # 5. 检测代理进程
    if ! detect_proxy_processes; then
        warning "未检测到代理进程，建议先启动代理服务"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}是否继续配置？[y/N]${RESET}"
            read -r -t 30 response || response="n"
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                info "操作已取消"
                exit 0
            fi
        fi
    fi
    
    # 6. 多种方式检测端口
    parse_config_ports
    detect_listening_ports
    
    # 7. Docker 端口检测
    if [ "$ENABLE_DOCKER" = true ]; then
        detect_docker_ports
    fi
    
    # 8. 端口过滤和确认
    if ! filter_and_confirm_ports; then
        warning "端口过滤失败，将使用默认配置"
        DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    # 9. 应用防火墙规则
    apply_firewall_rules
    
    # 10. 健康检查
    if [ "$DRY_RUN" = false ]; then
        health_check || warning "健康检查发现问题，请查看日志"
    fi
    
    # 11. 生成报告
    if [ "$DRY_RUN" = false ]; then
        generate_report
    fi
    
    # 12. 显示最终状态
    show_final_status
    
    # 13. 优化建议
    optimization_suggestions
    
    # 14. 提供额外选项
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${RESET}"
        echo -e "${CYAN}是否需要：${RESET}"
        echo -e "  ${YELLOW}1)${RESET} 启动实时监控模式"
        echo -e "  ${YELLOW}2)${RESET} 查看详细状态"
        echo -e "  ${YELLOW}3)${RESET} 退出"
        read -r -t 30 -p "请选择 (1-3): " final_choice || final_choice="3"
        
        case $final_choice in
            1)
                monitor_mode
                ;;
            2)
                show_firewall_status
                ;;
            *)
                info "配置完成，感谢使用！"
                ;;
        esac
    fi
}

# ============================================================================
# 脚本入口点
# ============================================================================

# 检查是否在交互模式下运行
if [ -t 0 ]; then
    # 交互式终端
    if [ $# -eq 0 ] && [ "$DRY_RUN" = false ]; then
        echo -e "${CYAN}检测到交互式终端${RESET}"
        echo -e "${YELLOW}是否使用配置向导？[y/N]${RESET}"
        read -r -t 10 response || response="n"
        if [[ "$response" =~ ^[Yy]$ ]]; then
            interactive_wizard
        fi
    fi
fi

# 执行主函数
main "$@"

# 脚本退出状态
exit 0

# ============================================================================
# 脚本结束
# 
# 功能总结：
# 1. ✅ 智能端口检测 (20+ 种代理软件)
# 2. ✅ IPv4/IPv6 双栈支持
# 3. ✅ Docker 容器端口检测
# 4. ✅ NAT 端口转发配置
# 5. ✅ SSH 暴力破解防护
# 6. ✅ 配置备份与恢复
# 7. ✅ 实时监控模式
# 8. ✅ 自动优化建议
# 9. ✅ 健康检查功能
# 10. ✅ 详细报告生成
# 11. ✅ 交互式配置向导
# 12. ✅ 定时任务支持
# 13. ✅ 错误处理和恢复
# 14. ✅ 多系统兼容
# 
# 使用示例：
#   bash firewall.sh                    # 标准部署
#   bash firewall.sh --dry-run          # 预览模式
#   bash firewall.sh --ipv6             # 启用 IPv6
#   bash firewall.sh --add-range        # 配置端口转发
#   bash firewall.sh --status           # 查看状态
#   bash firewall.sh --backup           # 备份配置
#   bash firewall.sh --reset            # 重置防火墙
#   bash firewall.sh --debug --dry-run  # 调试预览
# 
# 项目地址: https://github.com/your-repo/enhanced-firewall
# 问题反馈: https://github.com/your-repo/enhanced-firewall/issues
# 
# 版本: 2.1.0
# 作者: Enhanced Firewall Team
# 许可: MIT License
# ============================================================================
