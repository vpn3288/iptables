#!/bin/bash
set -e

# Color definitions
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# Script information
SCRIPT_VERSION="2.0.2"
SCRIPT_NAME="Precise Proxy Port Firewall Management Script (iptables version)"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}Optimized for Hiddify, 3X-UI, X-UI, Sing-box, Xray and other proxy panels${RESET}"
echo -e "${GREEN}🔧 Using iptables for best compatibility${RESET}"

# Permission check
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ Root privileges required${RESET}"
    exit 1
fi

# Global variables
DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
PORT_RANGES=()
NAT_RULES=()
OPENED_PORTS=0

# Default permanent open ports
DEFAULT_OPEN_PORTS=(80 443)

# Proxy core processes
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    "trojan" "trojan-go" "trojan-plus"
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
)

# Web panel processes
WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" "haproxy" "envoy"
)

# Proxy configuration files
PROXY_CONFIG_FILES=(
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/log/system/hiddify-panel.log"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/opt/hiddify-manager/.env"
    "/etc/x-ui/config.json"
    "/opt/3x-ui/bin/config.json"
    "/usr/local/x-ui/bin/config.json"
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    "/etc/hysteria/config.json"
    "/etc/tuic/config.json"
    "/etc/trojan/config.json"
)

# Common Hiddify ports
HIDDIFY_COMMON_PORTS=(
    "443" "8443" "9443"
    "80" "8080" "8880"
    "2053" "2083" "2087" "2096"
    "8443" "8880"
)

# Standard proxy ports
STANDARD_PROXY_PORTS=(
    "80" "443" "8080" "8443" "8880" "8888"
    "1080" "1085"
    "8388" "8389" "9000" "9001"
    "2080" "2443" "3128" "8964"
    "8443" "9443"
)

# Internal service ports (should not be exposed)
INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 3001 8000 8001
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    54321 62789
    9000 9001 9002
    8090 8091 8092 8093 8094 8095
)

# Dangerous port blacklist
BLACKLIST_PORTS=(
    22 23 25 53 69 111 135 137 138 139 445 514 631
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902
    110 143 465 587 993 995
    8181 10085 10086
)

# Helper functions
debug_log() { 
    if [ "$DEBUG_MODE" = true ]; then 
        echo -e "${BLUE}[DEBUG] $1${RESET}"
    fi
}

error_exit() { 
    echo -e "${RED}❌ $1${RESET}"
    exit 1
}

warning() { 
    echo -e "${YELLOW}⚠️  $1${RESET}"
}

success() { 
    echo -e "${GREEN}✅ $1${RESET}"
}

info() { 
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

# String split function
split_nat_rule() {
    local rule="$1"
    local delimiter="$2"
    local field="$3"
    
    if [ "$delimiter" = "->" ]; then
        if [ "$field" = "1" ]; then
            echo "${rule%->*}"
        elif [ "$field" = "2" ]; then
            echo "${rule#*->}"
        fi
    else
        echo "$rule" | cut -d"$delimiter" -f"$field"
    fi
}

# Show help
show_help() {
    cat << 'EOF'
Precise Proxy Port Firewall Management Script v2.0.2 (iptables version)

Intelligent port management tool designed for modern proxy panels

Usage: bash script.sh [options]

Options:
    --debug           Show detailed debugging information
    --dry-run         Preview mode, don't actually modify firewall
    --add-range       Interactive port range addition
    --reset           Reset firewall to default state
    --status          Show current firewall status
    --help, -h        Show this help

Supported proxy panels/software:
    ✓ Hiddify Manager/Panel
    ✓ 3X-UI / X-UI
    ✓ Xray / V2Ray
    ✓ Sing-box
    ✓ Hysteria / Hysteria2
    ✓ Trojan-Go / Trojan
    ✓ Shadowsocks series
    ✓ Other mainstream proxy tools

Security features:
    ✓ Precise port identification
    ✓ Automatic internal service port filtering
    ✓ Dangerous port filtering
    ✓ SSH brute force protection
    ✓ Stable iptables-based firewall

EOF
}

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug) DEBUG_MODE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --add-range) add_port_range_interactive; exit 0 ;;
            --reset) reset_firewall; exit 0 ;;
            --status) show_firewall_status; exit 0 ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "Unknown parameter: $1" ;;
        esac
    done
}

# Check system environment
check_system() {
    info "Checking system environment..."
    
    local tools=("iptables" "ss" "jq")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        info "Installing missing tools: ${missing_tools[*]}"
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
    
    success "System environment check completed"
}

# Detect SSH port
detect_ssh_port() {
    debug_log "Detecting SSH port..."
    
    local ssh_port=$(ss -tlnp 2>/dev/null | grep -E ':22\b|sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    info "Detected SSH port: $SSH_PORT"
}

# Detect existing NAT rules
detect_existing_nat_rules() {
    info "Detecting existing port forwarding rules..."
    
    local nat_rules=()
    
    if command -v iptables >/dev/null 2>&1; then
        debug_log "Scanning iptables PREROUTING NAT rules..."
        
        while IFS= read -r line; do
            if [[ "$line" =~ ^(num|Chain|\-\-\-|$) ]]; then
                continue
            fi
            
            debug_log "Analyzing iptables rule: $line"
            
            if echo "$line" | grep -qE "(DNAT|dnat)"; then
                local port_range=""
                local target_port=""
                
                if echo "$line" | grep -qE "dpts:[0-9]+:[0-9]+"; then
                    port_range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | sed 's/dpts://' | sed 's/:/-/')
                elif echo "$line" | grep -qE "dports [0-9]+:[0-9]+"; then
                    port_range=$(echo "$line" | grep -oE "dports [0-9]+:[0-9]+" | awk '{print $2}' | sed 's/:/-/')
                elif echo "$line" | grep -qE "dport [0-9]+-[0-9]+"; then
                    port_range=$(echo "$line" | grep -oE "dport [0-9]+-[0-9]+" | awk '{print $2}')
                fi
                
                if echo "$line" | grep -qE "to:[0-9\.]*:[0-9]+"; then
                    target_port=$(echo "$line" | grep -oE "to:[0-9\.]*:[0-9]+" | grep -oE "[0-9]+$")
                elif echo "$line" | grep -qE "to-destination [0-9\.]*:[0-9]+"; then
                    target_port=$(echo "$line" | grep -oE "to-destination [0-9\.]*:[0-9]+" | grep -oE "[0-9]+$")
                elif echo "$line" | grep -qE "\-\-to [0-9\.]*:[0-9]+"; then
                    target_port=$(echo "$line" | grep -oE "\-\-to [0-9\.]*:[0-9]+" | grep -oE "[0-9]+$")
                fi
                
                if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                    local rule_key="$port_range->$target_port"
                    nat_rules+=("$rule_key")
                    debug_log "Found iptables port forwarding rule: $port_range -> $target_port"
                fi
            fi
        done <<< "$(iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null)"
    fi
    
    if [ ${#nat_rules[@]} -gt 0 ]; then
        local unique_rules=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        NAT_RULES=("${unique_rules[@]}")
        
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ]; then
                DETECTED_PORTS+=("$target_port")
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔄 Detected existing port forwarding rules:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        success "Detected ${#NAT_RULES[@]} port forwarding rules"
    else
        info "No existing port forwarding rules detected"
    fi
}

# Interactive port range addition
add_port_range_interactive() {
    echo -e "${CYAN}🔧 Configure port forwarding rules${RESET}"
    echo -e "${YELLOW}Port forwarding allows redirecting a port range to a single target port${RESET}"
    echo -e "${YELLOW}Example: 16820-16888 forwards to 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}Please enter port range (format: start-end, like 16820-16888):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_port="${BASH_REMATCH[1]}"
            local end_port="${BASH_REMATCH[2]}"
            
            if [ "$start_port" -ge "$end_port" ]; then
                echo -e "${RED}Start port must be less than end port${RESET}"
                continue
            fi
            
            echo -e "${CYAN}Please enter target port (single port number):${RESET}"
            read -r target_port
            
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                DETECTED_PORTS+=("$target_port")
                success "Added port forwarding rule: $port_range -> $target_port"
                
                echo -e "${YELLOW}Continue adding other port forwarding rules? [y/N]${RESET}"
                read -r response
                if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    break
                fi
            else
                echo -e "${RED}Invalid target port: $target_port${RESET}"
            fi
        else
            echo -e "${RED}Invalid port range format: $port_range${RESET}"
        fi
    done
}

# Detect proxy processes
detect_proxy_processes() {
    info "Detecting proxy service processes..."
    
    local found_processes=()
    
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "Found proxy process: $process"
        fi
    done
    
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "Found web panel process: $process"
        fi
    done
    
    if [ ${#found_processes[@]} -gt 0 ]; then
        success "Detected proxy-related processes: ${found_processes[*]}"
        return 0
    else
        warning "No running proxy processes detected"
        return 1
    fi
}

# Check bind address type
check_bind_address() {
    local address="$1"
    
    if [[ "$address" =~ ^(\*|0\.0\.0\.0|\[::\]|::): ]]; then
        echo "public"
    elif [[ "$address" =~ ^(127\.|::1|\[::1\]): ]]; then
        echo "localhost"
    elif [[ "$address" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.): ]]; then
        echo "private"
    else
        echo "unknown"
    fi
}

# Parse ports from config files
parse_config_ports() {
    info "Parsing ports from configuration files..."
    
    local config_ports=()
    
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "Analyzing config file: $config_file"
            
            if [[ "$config_file" =~ \.json$ ]]; then
                if command -v jq >/dev/null 2>&1; then
                    local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "Parsed port from $config_file: $port"
                            fi
                        done <<< "$ports"
                    fi
                fi
            elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "Parsed YAML port from $config_file: $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "Parsed ${#unique_ports[@]} ports from configuration files"
    fi
}

# Detect listening ports
detect_listening_ports() {
    info "Detecting currently listening ports..."
    
    local listening_ports=()
    local localhost_ports=()
    
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local protocol=$(echo "$line" | awk '{print tolower($1)}')
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            
            local process="unknown"
            if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
                process="${BASH_REMATCH[1]}"
            fi
            
            local bind_type=$(check_bind_address "$address_port")
            
            debug_log "Detected listening: $address_port ($protocol, $process, $bind_type)"
            
            if is_proxy_related "$process" && [ -n "$port" ] && [ "$port" != "$SSH_PORT" ]; then
                if [ "$bind_type" = "public" ]; then
                    if ! is_internal_service_port "$port"; then
                        listening_ports+=("$port")
                        debug_log "Detected public proxy port: $port ($protocol, $process)"
                    else
                        debug_log "Skipped internal service port: $port"
                    fi
                elif [ "$bind_type" = "localhost" ]; then
                    localhost_ports+=("$port")
                    debug_log "Detected local proxy port: $port ($protocol, $process) - not exposed"
                fi
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    if [ ${#localhost_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 Detected internal service ports (localhost only):${RESET}"
        for port in $(printf '%s\n' "${localhost_ports[@]}" | sort -nu); do
            echo -e "  ${YELLOW}• $port${RESET} - Internal service, not exposed"
        done
    fi
    
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "Detected ${#unique_ports[@]} public listening ports"
    fi
}

# Check if process is proxy-related
is_proxy_related() {
    local process="$1"
    
    for proxy_proc in "${PROXY_CORE_PROCESSES[@]}" "${WEB_PANEL_PROCESSES[@]}"; do
        if [[ "$process" == *"$proxy_proc"* ]]; then
            return 0
        fi
    done
    
    if [[ "$process" =~ (proxy|vpn|tunnel|shadowsocks|trojan|v2ray|xray|clash|hysteria|sing) ]]; then
        return 0
    fi
    
    return 1
}

# Check if port is internal service
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# Check if port is standard proxy port
is_standard_proxy_port() {
    local port="$1"
    
    local common_ports=(80 443 1080 1085 8080 8388 8443 8880 8888 9443)
    for common_port in "${common_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    if [ "$port" -ge 30000 ] && [ "$port" -le 39999 ]; then
        return 0
    fi
    if [ "$port" -ge 40000 ] && [ "$port" -le 65000 ] && ! is_internal_service_port "$port"; then
        return 0
    fi
    
    return 1
}

# Port safety check
is_port_safe() {
    local port="$1"
    
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then
            debug_log "Port $port is blacklisted"
            return 1
        fi
    done
    
    if is_internal_service_port "$port"; then
        debug_log "Port $port is internal service port"
        return 1
    fi
    
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        debug_log "Port $port out of valid range"
        return 1
    fi
    
    if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
        debug_log "Port $port is default open port"
        return 0
    fi
    
    return 0
}

# Filter and confirm ports
filter_and_confirm_ports() {
    info "Intelligent port analysis and confirmation..."
    
    info "Adding default open ports: ${DEFAULT_OPEN_PORTS[*]}"
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    local suspicious_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
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
    
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ Standard proxy ports (recommended):${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} - Default open port"
            else
                echo -e "  ${GREEN}✓ $port${RESET} - Common proxy port"
            fi
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 Internal service ports (filtered):${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "  ${YELLOW}- $port${RESET} - Internal service port, not exposed"
        done
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}⚠️  Suspicious ports (require confirmation):${RESET}"
        for port in "${suspicious_ports[@]}"; do
            echo -e "  ${YELLOW}? $port${RESET} - Not a standard proxy port"
        done
        
        echo -e "\n${YELLOW}These ports may not be necessary proxy ports${RESET}"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}Open these suspicious ports too? [y/N]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                safe_ports+=("${suspicious_ports[@]}")
                info "User confirmed opening suspicious ports"
            else
                info "Skipping suspicious ports"
            fi
        fi
    fi
    
    if [ ${#unsafe_ports[@]} -gt 0 ]; then
        echo -e "\n${RED}❌ Dangerous ports (skipped):${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "  ${RED}✗ $port${RESET} - System port or dangerous port"
        done
    fi
    
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 Configure port forwarding functionality? [y/N]${RESET}"
        echo -e "${YELLOW}Port forwarding can redirect a port range to a single target port${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "No standard proxy ports detected"
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}📋 Final ports to open:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (default open)"
            else
                echo -e "  ${CYAN}• $port${RESET}"
            fi
        done
        
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "\n${CYAN}🔄 Port forwarding rules:${RESET}"
            for rule in "${NAT_RULES[@]}"; do
                echo -e "  ${CYAN}• $rule${RESET}"
            done
        fi
        
        echo -e "\n${YELLOW}Confirm opening ${#safe_ports[@]} ports"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "and ${#NAT_RULES[@]} port forwarding rules"
        fi
        echo -e "? [Y/n]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]?$ ]]; then
            info "User cancelled operation"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# Clean existing firewalls
cleanup_firewalls() {
    info "Cleaning existing firewall configuration..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[Preview mode] Will clean existing firewall"
        return 0
    fi
    
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "Disabled $service"
        fi
    done
    
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # Backup existing NAT rules
    local nat_backup="/tmp/nat_rules_backup.txt"
    iptables-save -t nat > "$nat_backup" 2>/dev/null || true
    
    # Clear filter table rules but keep basic policies
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F INPUT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    
    # Clear custom chains
    iptables -X 2>/dev/null || true
    
    success "Firewall cleanup completed (NAT rules preserved)"
}

# Setup SSH protection
setup_ssh_protection() {
    info "Setting up SSH brute force protection..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[Preview mode] Will setup SSH protection"
        return 0
    fi
    
    # Create SSH protection chain
    iptables -N SSH_PROTECTION 2>/dev/null || true
    iptables -F SSH_PROTECTION 2>/dev/null || true
    
    # SSH brute force protection rules
    iptables -A SSH_PROTECTION -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP
    iptables -A SSH_PROTECTION -m recent --name ssh_attempts --set
    iptables -A SSH_PROTECTION -j ACCEPT
    
    success "SSH brute force protection configured"
}

# Apply iptables rules
apply_firewall_rules() {
    info "Applying iptables firewall rules..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[Preview mode] Firewall rules preview:"
        show_rules_preview
        return 0
    fi
    
    # Set default policies (ACCEPT first to avoid lockout)
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Basic rules: allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Basic rules: allow established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # ICMP support (network diagnostics)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT
    
    # SSH protection
    setup_ssh_protection
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j SSH_PROTECTION
    
    # Open proxy ports (TCP and UDP)
    for port in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        debug_log "Opened port: $port (TCP/UDP)"
    done
    
    # Apply NAT rules (port forwarding)
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "Applying port forwarding rules..."
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                local start_port=$(echo "$port_range" | cut -d'-' -f1)
                local end_port=$(echo "$port_range" | cut -d'-' -f2)
                
                # Add DNAT rules
                iptables -t nat -A PREROUTING -p udp --dport "$start_port:$end_port" -j DNAT --to-destination ":$target_port"
                iptables -t nat -A PREROUTING -p tcp --dport "$start_port:$end_port" -j DNAT --to-destination ":$target_port"
                
                # Open port range
                iptables -A INPUT -p tcp --dport "$start_port:$end_port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$start_port:$end_port" -j ACCEPT
                
                success "Applied port forwarding: $port_range -> $target_port"
                debug_log "NAT rule: $start_port:$end_port -> $target_port"
            else
                warning "Cannot parse NAT rule: $rule"
            fi
        done
    fi
    
    # Log and drop other connections (limit log frequency)
    iptables -A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "iptables-drop: " --log-level 4
    
    # Finally set default drop policy
    iptables -P INPUT DROP
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "iptables rules applied successfully"
    
    # Save rules
    save_iptables_rules
}

# Save iptables rules
save_iptables_rules() {
    info "Saving iptables rules..."
    
    if command -v iptables-save >/dev/null 2>&1; then
        if [ -d "/etc/iptables" ]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            
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
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            systemctl enable iptables >/dev/null 2>&1 || true
            
        else
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
        success "iptables rules saved"
    else
        warning "Cannot save iptables rules, rules will be lost after reboot"
    fi
}

# Show rules preview
show_rules_preview() {
    echo -e "${CYAN}📋 iptables rules preview to be applied:${RESET}"
    echo
    echo "# Basic rules"
    echo "iptables -P INPUT DROP"
    echo "iptables -P FORWARD DROP"
    echo "iptables -P OUTPUT ACCEPT"
    echo "iptables -A INPUT -i lo -j ACCEPT"
    echo "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo
    echo "# ICMP support"
    echo "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT"
    echo
    echo "# SSH protection"
    echo "iptables -A INPUT -p tcp --dport $SSH_PORT -m recent --name ssh_attempts --update --seconds 60 --hitcount 4 -j DROP"
    echo "iptables -A INPUT -p tcp --dport $SSH_PORT -m recent --name ssh_attempts --set -j ACCEPT"
    echo
    echo "# Proxy ports"
    for port in "${DETECTED_PORTS[@]}"; do
        echo "iptables -A INPUT -p tcp --dport $port -j ACCEPT"
        echo "iptables -A INPUT -p udp --dport $port -j ACCEPT"
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo
        echo "# Port forwarding rules"
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
    echo "# Logging and drop"
    echo "iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix 'iptables-drop: '"
    echo "iptables -A INPUT -j DROP"
}

# Verify port forwarding functionality
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "Verifying port forwarding configuration..."
        
        echo -e "\n${CYAN}🔍 Current NAT rules status:${RESET}"
        if command -v iptables >/dev/null 2>&1; then
            iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep DNAT || echo "No NAT rules"
        fi
        
        echo -e "\n${YELLOW}💡 Port forwarding usage instructions:${RESET}"
        echo -e "  - Clients can connect to any port within the range"
        echo -e "  - All connections will be forwarded to the target port"
        echo -e "  - Example: connections to any port in range forward to target port"
        
        local checked_ports=()
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            debug_log "Verifying rule: $port_range -> $target_port"
            
            if [ -n "$target_port" ]; then
                if [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                    checked_ports+=("$target_port")
                    
                    if ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                        echo -e "  ${GREEN}✓ Target port $target_port is listening${RESET}"
                    else
                        echo -e "  ${YELLOW}⚠️  Target port $target_port is not listening${RESET}"
                        echo -e "    ${YELLOW}Hint: Please ensure proxy service is running on port $target_port${RESET}"
                    fi
                fi
            else
                echo -e "  ${RED}❌ Cannot parse rule: $rule${RESET}"
            fi
        done
        
        echo -e "\n${CYAN}📝 Port forwarding rules summary:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• Port range $port_range → Target port $target_port${RESET}"
        done
    fi
}

# Reset firewall
reset_firewall() {
    echo -e "${YELLOW}🔄 Reset firewall to default state${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}Warning: This will clear all iptables rules!${RESET}"
        echo -e "${YELLOW}Confirm firewall reset? [y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            info "Reset operation cancelled"
            return 0
        fi
    fi
    
    info "Resetting iptables rules..."
    
    if [ "$DRY_RUN" = false ]; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        
        save_iptables_rules
        
        success "Firewall reset to default state"
    else
        info "[Preview mode] Will reset all iptables rules"
    fi
}

# Show firewall status
show_firewall_status() {
    echo -e "${CYAN}🔍 Current firewall status${RESET}"
    echo
    
    echo -e "${GREEN}📊 iptables rules statistics:${RESET}"
    local input_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | wc -l)
    local nat_rules=$(iptables -t nat -L PREROUTING --line-numbers 2>/dev/null | wc -l)
    echo -e "  INPUT rules: $((input_rules - 2))"
    echo -e "  NAT rules: $((nat_rules - 2))"
    echo
    
    echo -e "${GREEN}🔓 Open ports:${RESET}"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E "dpt:[0-9]+" | while read -r line; do
        local port=$(echo "$line" | grep -oE "dpt:[0-9]+" | cut -d: -f2)
        local protocol=$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
        if [ -n "$port" ]; then
            echo -e "  • $port ($protocol)"
        fi
    done
    echo
    
    echo -e "${GREEN}🔄 Port forwarding rules:${RESET}"
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
        echo -e "  ${YELLOW}No port forwarding rules${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🛡️  SSH protection status:${RESET}"
    if iptables -L INPUT -n 2>/dev/null | grep -q "recent:"; then
        echo -e "  ${GREEN}✓ SSH brute force protection enabled${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  SSH brute force protection not enabled${RESET}"
    fi
    echo
    
    echo -e "${CYAN}🔧 Management commands:${RESET}"
    echo -e "  ${YELLOW}View all rules:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}View NAT rules:${RESET} iptables -t nat -L -n -v"
    echo -e "  ${YELLOW}View listening ports:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}Reconfigure:${RESET} bash $0"
    echo -e "  ${YELLOW}Reset firewall:${RESET} bash $0 --reset"
}

# Show final status
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 iptables firewall configuration completed!"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 Configuration summary:${RESET}"
    echo -e "  ${GREEN}✓ Opened ports: $OPENED_PORTS${RESET}"
    echo -e "  ${GREEN}✓ SSH port: $SSH_PORT (protected)${RESET}"
    echo -e "  ${GREEN}✓ Firewall engine: iptables${RESET}"
    echo -e "  ${GREEN}✓ Internal service protection: enabled${RESET}"
    echo -e "  ${GREEN}✓ Default ports: 80, 443 (permanently open)${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓ Port forwarding rules: ${#unique_nat_rules[@]}${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 Opened ports:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - Default open${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 Port forwarding rules:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• $port_range → $target_port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 This was preview mode, firewall not actually modified${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 Management commands:${RESET}"
    echo -e "  ${YELLOW}View rules:${RESET} iptables -L -n -v"
    echo -e "  ${YELLOW}View ports:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}View NAT rules:${RESET} iptables -t nat -L -n -v"
    echo -e "  ${YELLOW}View status:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}Add port forwarding:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}Reset firewall:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ Proxy ports precisely opened, port forwarding configured, internal services protected, server security enabled!${RESET}"
    
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
            echo -e "\n${YELLOW}⚠️  Reminder: Some port forwarding target ports are not listening${RESET}"
            echo -e "${YELLOW}   Please ensure related proxy services are running, otherwise port forwarding may not work${RESET}"
        fi
    fi
}

# Main function
main() {
    trap 'echo -e "\n${RED}Operation interrupted${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 Starting intelligent proxy port detection and configuration...${RESET}"
    
    check_system
    detect_ssh_port
    detect_existing_nat_rules
    cleanup_firewalls
    
    if ! detect_proxy_processes; then
        warning "Recommend starting proxy services before running this script for best results"
    fi
    
    parse_config_ports
    detect_listening_ports
    
    if ! filter_and_confirm_ports; then
        info "Adding Hiddify common ports as backup..."
        DETECTED_PORTS=("${HIDDIFY_COMMON_PORTS[@]}")
        if ! filter_and_confirm_ports; then
            error_exit "Cannot determine ports to open"
        fi
    fi
    
    apply_firewall_rules
    verify_port_hopping
    show_final_status
}

# Script entry point
main "$@"
