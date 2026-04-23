#!/bin/bash

# Hysteria2 Port Hopping Firewall Script - Optimized Version 4.5
# Author: 老G (Code Review Expert)
# Optimized for: Enhanced reliability, precise rule management, comprehensive error handling
# Date: $(date +%Y-%m-%d)

set -euo pipefail  # 严格错误处理模式

# 全局配置
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/hysteria2-firewall.log"
readonly LOCK_FILE="/var/run/hysteria2-firewall.lock"
readonly MAX_RETRIES=3
readonly RETRY_DELAY=2

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# 日志函数
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

# 错误处理函数
error_exit() {
    log_error "$1"
    cleanup
    exit 1
}

# 清理函数
cleanup() {
    [[ -f "$LOCK_FILE" ]] && rm -f "$LOCK_FILE"
}

# 信号处理
trap cleanup EXIT INT TERM

# 锁文件检查
check_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            error_exit "脚本已在运行中 (PID: $pid)"
        else
            log_warn "发现过期锁文件，正在清理"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

# 权限检查
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "此脚本需要root权限运行"
    fi
}

# IPv6支持检查 - 增强版
check_ipv6_support() {
    log_debug "检查IPv6支持状态"
    
    # 检查内核IPv6支持
    if [[ ! -f /proc/net/if_inet6 ]]; then
        log_warn "内核不支持IPv6"
        return 1
    fi
    
    # 检查IPv6是否被禁用
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        local ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
        if [[ "$ipv6_disabled" == "1" ]]; then
            log_warn "IPv6已被系统禁用"
            return 1
        fi
    fi
    
    # 检查ip6tables命令
    if ! command -v ip6tables >/dev/null 2>&1; then
        log_warn "ip6tables命令不可用"
        return 1
    fi
    
    # 测试ip6tables基本功能
    if ! ip6tables -L >/dev/null 2>&1; then
        log_warn "ip6tables无法正常工作"
        return 1
    fi
    
    log_info "IPv6支持检查通过"
    return 0
}

# 端口有效性检查
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        return 1
    fi
    return 0
}

# 端口范围有效性检查
validate_port_range() {
    local start_port="$1"
    local end_port="$2"
    
    if ! validate_port "$start_port" || ! validate_port "$end_port"; then
        return 1
    fi
    
    if [[ "$start_port" -ge "$end_port" ]]; then
        log_error "起始端口($start_port)必须小于结束端口($end_port)"
        return 1
    fi
    
    local range_size=$((end_port - start_port + 1))
    if [[ "$range_size" -gt 10000 ]]; then
        log_warn "端口范围过大($range_size个端口)，可能影响性能"
    fi
    
    return 0
}

# 端口冲突检查 - 新增功能
check_port_conflicts() {
    local target_port="$1"
    local start_port="$2"
    local end_port="$3"
    
    log_debug "检查端口冲突: 目标端口$target_port, 范围$start_port-$end_port"
    
    # 检查目标端口是否在跳跃范围内
    if [[ "$target_port" -ge "$start_port" ]] && [[ "$target_port" -le "$end_port" ]]; then
        log_error "目标端口$target_port不能在跳跃端口范围($start_port-$end_port)内"
        return 1
    fi
    
    # 检查端口是否被占用
    if ss -tuln | grep -q ":$target_port "; then
        log_warn "目标端口$target_port已被其他服务占用"
        read -p "是否继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    return 0
}

# 精确规则匹配和清理 - 核心优化
clean_existing_rules() {
    local target_port="$1"
    local start_port="$2" 
    local end_port="$3"
    
    log_info "清理现有的端口跳跃规则 (端口范围: $start_port-$end_port -> $target_port)"
    
    # IPv4规则清理 - 使用awk进行精确匹配
    log_debug "清理IPv4 PREROUTING规则"
    local ipv4_rules_to_delete=()
    while IFS= read -r line_num; do
        [[ -n "$line_num" ]] && ipv4_rules_to_delete+=("$line_num")
    done < <(iptables -t nat -L PREROUTING --line-numbers -n | \
        awk -v start="$start_port" -v end="$end_port" -v target="$target_port" '
        /^[0-9]+/ {
            if ($0 ~ "dpt:" start ":" end && $0 ~ "to:" target) {
                print $1
            }
        }' | sort -rn)
    
    # 删除匹配的IPv4规则
    for rule_num in "${ipv4_rules_to_delete[@]}"; do
        log_debug "删除IPv4规则 #$rule_num"
        if ! iptables -t nat -D PREROUTING "$rule_num" 2>/dev/null; then
            log_warn "删除IPv4规则 #$rule_num 失败"
        fi
    done
    
    # IPv6规则清理 (如果支持)
    if check_ipv6_support; then
        log_debug "清理IPv6 PREROUTING规则"
        local ipv6_rules_to_delete=()
        while IFS= read -r line_num; do
            [[ -n "$line_num" ]] && ipv6_rules_to_delete+=("$line_num")
        done < <(ip6tables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | \
            awk -v start="$start_port" -v end="$end_port" -v target="$target_port" '
            /^[0-9]+/ {
                if ($0 ~ "dpt:" start ":" end && $0 ~ "to:\\[\\]:" target) {
                    print $1
                }
            }' | sort -rn)
        
        # 删除匹配的IPv6规则
        for rule_num in "${ipv6_rules_to_delete[@]}"; do
            log_debug "删除IPv6规则 #$rule_num"
            if ! ip6tables -t nat -D PREROUTING "$rule_num" 2>/dev/null; then
                log_warn "删除IPv6规则 #$rule_num 失败"
            fi
        done
    fi
    
    log_info "规则清理完成"
}

# 重试机制包装器
retry_command() {
    local cmd="$1"
    local description="$2"
    local attempt=1
    
    while [[ $attempt -le $MAX_RETRIES ]]; do
        log_debug "执行: $description (尝试 $attempt/$MAX_RETRIES)"
        
        if eval "$cmd"; then
            log_debug "$description 执行成功"
            return 0
        else
            log_warn "$description 执行失败 (尝试 $attempt/$MAX_RETRIES)"
            if [[ $attempt -lt $MAX_RETRIES ]]; then
                log_debug "等待 ${RETRY_DELAY}s 后重试"
                sleep $RETRY_DELAY
            fi
            ((attempt++))
        fi
    done
    
    log_error "$description 在 $MAX_RETRIES 次尝试后仍然失败"
    return 1
}

# 规则验证函数 - 新增功能
verify_rules() {
    local target_port="$1"
    local start_port="$2"
    local end_port="$3"
    
    log_info "验证防火墙规则是否正确应用"
    
    # 验证IPv4规则
    local ipv4_rule_count=$(iptables -t nat -L PREROUTING -n | \
        grep -c "dpt:$start_port:$end_port.*to:.*:$target_port" || true)
    
    if [[ "$ipv4_rule_count" -eq 0 ]]; then
        log_error "IPv4端口跳跃规则验证失败"
        return 1
    fi
    
    log_info "IPv4规则验证通过 (找到 $ipv4_rule_count 条规则)"
    
    # 验证IPv6规则 (如果支持)
    if check_ipv6_support; then
        local ipv6_rule_count=$(ip6tables -t nat -L PREROUTING -n 2>/dev/null | \
            grep -c "dpt:$start_port:$end_port.*to:\[\]:$target_port" || true)
        
        if [[ "$ipv6_rule_count" -eq 0 ]]; then
            log_warn "IPv6端口跳跃规则验证失败"
        else
            log_info "IPv6规则验证通过 (找到 $ipv6_rule_count 条规则)"
        fi
    fi
    
    return 0
}

# 应用端口跳跃规则 - 核心功能优化
apply_hop() {
    local target_port="$1"
    local start_port="$2"
    local end_port="$3"
    
    log_info "${BLUE}开始应用端口跳跃规则${NC}"
    log_info "配置: $start_port-$end_port -> $target_port"
    
    # 参数验证
    if ! validate_port_range "$start_port" "$end_port" || ! validate_port "$target_port"; then
        error_exit "端口参数验证失败"
    fi
    
    # 端口冲突检查
    if ! check_port_conflicts "$target_port" "$start_port" "$end_port"; then
        error_exit "端口冲突检查失败"
    fi
    
    # 清理现有规则
    clean_existing_rules "$target_port" "$start_port" "$end_port"
    
    # 应用IPv4规则
    log_info "应用IPv4端口跳跃规则"
    local ipv4_cmd="iptables -t nat -A PREROUTING -p tcp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
    if ! retry_command "$ipv4_cmd" "IPv4 TCP规则"; then
        error_exit "IPv4 TCP规则应用失败"
    fi
    
    local ipv4_udp_cmd="iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination :$target_port"
    if ! retry_command "$ipv4_udp_cmd" "IPv4 UDP规则"; then
        error_exit "IPv4 UDP规则应用失败"
    fi
    
    # 应用IPv6规则 (如果支持)
    if check_ipv6_support; then
        log_info "应用IPv6端口跳跃规则"
        local ipv6_cmd="ip6tables -t nat -A PREROUTING -p tcp --dport $start_port:$end_port -j DNAT --to-destination [::]:$target_port"
        if ! retry_command "$ipv6_cmd" "IPv6 TCP规则"; then
            log_warn "IPv6 TCP规则应用失败，但继续执行"
        fi
        
        local ipv6_udp_cmd="ip6tables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination [::]:$target_port"
        if ! retry_command "$ipv6_udp_cmd" "IPv6 UDP规则"; then
            log_warn "IPv6 UDP规则应用失败，但继续执行"
        fi
    fi
    
    # 验证规则
    if ! verify_rules "$target_port" "$start_port" "$end_port"; then
        error_exit "规则验证失败"
    fi
    
    log_info "${GREEN}端口跳跃规则应用成功${NC}"
    log_info "端口范围 $start_port-$end_port 现在会跳转到端口 $target_port"
}

# 移除端口跳跃规则
remove_hop() {
    local target_port="$1"
    local start_port="$2"
    local end_port="$3"
    
    log_info "${YELLOW}开始移除端口跳跃规则${NC}"
    log_info "配置: $start_port-$end_port -> $target_port"
    
    # 参数验证
    if ! validate_port_range "$start_port" "$end_port" || ! validate_port "$target_port"; then
        error_exit "端口参数验证失败"
    fi
    
    # 清理规则
    clean_existing_rules "$target_port" "$start_port" "$end_port"
    
    log_info "${GREEN}端口跳跃规则移除完成${NC}"
}

# 显示当前规则
show_rules() {
    log_info "${BLUE}当前防火墙规则状态${NC}"
    
    echo -e "\n${YELLOW}=== IPv4 NAT PREROUTING 规则 ===${NC}"
    iptables -t nat -L PREROUTING -n --line-numbers
    
    if check_ipv6_support; then
        echo -e "\n${YELLOW}=== IPv6 NAT PREROUTING 规则 ===${NC}"
        ip6tables -t nat -L PREROUTING -n --line-numbers 2>/dev/null || log_warn "无法显示IPv6规则"
    fi
    
    echo -e "\n${YELLOW}=== 端口占用情况 ===${NC}"
    ss -tuln | head -20
}

# 显示帮助信息
show_help() {
    cat << EOF
${BLUE}Hysteria2 端口跳跃防火墙脚本 - 优化版本 4.5${NC}

用法: $SCRIPT_NAME <命令> [参数]

命令:
  apply <目标端口> <起始端口> <结束端口>  应用端口跳跃规则
  remove <目标端口> <起始端口> <结束端口> 移除端口跳跃规则
  show                                   显示当前规则
  help                                   显示此帮助信息

示例:
  $SCRIPT_NAME apply 8080 10000 20000   # 将10000-20000端口跳转到8080
  $SCRIPT_NAME remove 8080 10000 20000  # 移除上述跳转规则
  $SCRIPT_NAME show                      # 显示当前所有规则

注意事项:
  - 此脚本需要root权限运行
  - 目标端口不能在跳跃端口范围内
  - 建议在应用规则前备份现有iptables配置
  - 支持IPv4和IPv6双栈配置

日志文件: $LOG_FILE
锁文件: $LOCK_FILE

作者: 老G (资深代码审查专家)
版本: 4.5 (优化版)
EOF
}

# 主函数
main() {
    # 初始化
    check_privileges
    check_lock
    
    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"
    
    log_info "=== Hysteria2防火墙脚本启动 (版本4.5) ==="
    log_info "命令行参数: $*"
    
    # 参数检查
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        "apply")
            if [[ $# -ne 3 ]]; then
                error_exit "apply命令需要3个参数: <目标端口> <起始端口> <结束端口>"
            fi
            apply_hop "$1" "$2" "$3"
            ;;
        "remove")
            if [[ $# -ne 3 ]]; then
                error_exit "remove命令需要3个参数: <目标端口> <起始端口> <结束端口>"
            fi
            remove_hop "$1" "$2" "$3"
            ;;
        "show")
            show_rules
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            error_exit "未知命令: $command。使用 '$SCRIPT_NAME help' 查看帮助"
            ;;
    esac
    
    log_info "=== 脚本执行完成 ==="
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi