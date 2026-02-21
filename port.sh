#!/bin/bash
set -e

# ==========================================
# 强化版 精确代理端口防火墙管理脚本 v3.0
# 专为隐蔽性、安全性、多面板兼容设计
# ==========================================

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

echo -e "${CYAN}==========================================${RESET}"
echo -e "${GREEN}🛡️ 强化版 精确代理防火墙管理脚本 v3.0${RESET}"
echo -e "${YELLOW}支持: Hiddify, X-UI, Sing-box, fscarmen, v2ray-agent, Hysteria2${RESET}"
echo -e "${CYAN}==========================================${RESET}"

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 请使用 root 权限运行此脚本 (sudo bash script.sh)${RESET}"
    exit 1
fi

# 全局变量
SSH_PORT="22"
DETECTED_PORTS=()
PORT_RANGES=()
NAT_RULES=()
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心与面板进程名
PROXY_PROCESSES=(
    "xray" "v2ray" "sing-box" "hysteria" "hysteria2" 
    "tuic" "hiddify" "x-ui" "3x-ui" "trojan" "clash" "mihomo"
    "nginx" "caddy" # 很多一键脚本依赖 Web Server 作为前置
)

# 常见面板和一键脚本的配置文件路径 (补充 fscarmen, v2ray-agent 等)
CONFIG_PATHS=(
    "/etc/x-ui/config.json"
    "/usr/local/x-ui/bin/config.json"
    "/etc/v2ray-agent/xray/conf/"
    "/etc/v2ray-agent/hysteria/conf/"
    "/usr/local/v2ray-agent/xray/conf/"
    "/etc/sing-box/config.json"
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/etc/hysteria/config.yaml"
)

# 安装依赖
install_dependencies() {
    echo -e "\n${CYAN}[1/6] 检查并安装必要依赖...${RESET}"
    if command -v apt-get >/dev/null; then
        apt-get update -qq
        apt-get install -y -qq iptables iptables-persistent iproute2 jq lsof net-tools
    elif command -v yum >/dev/null; then
        yum install -y -q iptables iptables-services iproute jq lsof net-tools
    fi
    echo -e "${GREEN}✅ 依赖安装完成。${RESET}"
}

# 绝对安全的规则重置（幂等性核心）
reset_firewall() {
    echo -e "\n${CYAN}[2/6] 安全重置防火墙规则...${RESET}"
    
    # 1. 默认策略先全部开放，防止操作中途断网
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # 2. 清空所有规则和自定义链
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    echo -e "${GREEN}✅ 防火墙已清空，处于干净初始状态。${RESET}"
}

# 检测 SSH 和 代理监听端口
detect_ports() {
    echo -e "\n${CYAN}[3/6] 智能探测动态监听端口...${RESET}"
    
    # 探测 SSH
    local ssh_port_detect=$(ss -tlnp 2>/dev/null | grep -E 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    if [[ "$ssh_port_detect" =~ ^[0-9]+$ ]]; then
        SSH_PORT=$ssh_port_detect
    fi
    echo -e "${GREEN}📍 识别到 SSH 端口: ${SSH_PORT}${RESET}"
    DETECTED_PORTS+=("$SSH_PORT")
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")

    # 扫描活跃的代理进程端口
    echo -e "${YELLOW}扫描运行中的代理进程 (ss 动态扫描)...${RESET}"
    for proc in "${PROXY_PROCESSES[@]}"; do
        local ports=$(ss -tulnp 2>/dev/null | grep -i "$proc" | awk '{print $5}' | awk -F: '{print $NF}' | grep -v "^$" | sort -u)
        for p in $ports; do
            if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ne 53 ] && [ "$p" -ge 1024 ] || [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $p " ]]; then
                # 过滤掉本地回环服务 (如仅监听在 127.0.0.1 的端口不向外网开放)
                local is_local=$(ss -tulnp 2>/dev/null | grep -i "$proc" | grep ":$p " | grep -E "127\.0\.0\.1|::1")
                if [ -z "$is_local" ]; then
                    DETECTED_PORTS+=("$p")
                    echo -e "  - 发现公网服务 [$proc]: $p"
                fi
            fi
        done
    done

    # 数组去重
    DETECTED_PORTS=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    echo -e "${GREEN}✅ 最终需开放的离散端口: ${DETECTED_PORTS[*]}${RESET}"
}

# Hysteria2 / 代理面板端口跳跃交互式配置
configure_port_hopping() {
    echo -e "\n${CYAN}[4/6] 端口跳跃与 NAT 转发配置 (针对 Hysteria2 等)${RESET}"
    echo -e "如果你的 Hysteria2/Sing-box 监听在 443，但你想让客户端通过 20000-30000 范围随机连接，可以在此设置。"
    
    read -p "是否需要配置端口段映射 (Port Hopping)? [y/N]: " setup_nat
    if [[ "$setup_nat" =~ ^[Yy]$ ]]; then
        read -p "请输入映射范围 (例如: 20000-30000): " port_range
        read -p "请输入目标监听端口 (例如: 443 或你的 Hysteria2 端口): " target_port
        
        if [[ "$port_range" =~ ^[0-9]+-[0-9]+$ ]] && [[ "$target_port" =~ ^[0-9]+$ ]]; then
            NAT_RULES+=("$port_range->$target_port")
            echo -e "${GREEN}✅ 已记录规则: 外部范围 $port_range 将转发至本地 $target_port${RESET}"
        else
            echo -e "${RED}❌ 格式错误，跳过此步骤。${RESET}"
        fi
    else
        echo -e "${YELLOW}跳过 NAT 端口映射配置。${RESET}"
    fi
}

# 构建隐蔽性与核心规则
build_firewall() {
    echo -e "\n${CYAN}[5/6] 注入隐蔽性优化与安全放行规则...${RESET}"
    
    # --- 1. 基础安全与隐蔽性规则 (Stealth) ---
    # 丢弃无效包 (防止各种奇怪的扫描器探针)
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    # 防御 TCP SYN 扫描 (隐蔽自身)
    iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    # 丢弃不合规的 TCP 标志组合 (XMAS, NULL 等扫描)
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    
    # 本地回环与已建立的连接放行
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 限制 ICMP (Ping) 频率，防止 Ping 洪泛，同时保持一定连通性
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/sec --limit-burst 5 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

    # --- 2. SSH 防暴力破解 ---
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -m recent --set --name SSH
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 --name SSH -j DROP

    # --- 3. 放行所有检测到的有效端口 (TCP & UDP) ---
    for port in "${DETECTED_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done

    # --- 4. 注入 NAT 端口跳跃规则 ---
    for rule in "${NAT_RULES[@]}"; do
        local range="${rule%->*}"
        local target="${rule#*->}"
        # 添加 DNAT
        iptables -t nat -A PREROUTING -p udp --dport "$range" -j DNAT --to-destination ":$target"
        iptables -t nat -A PREROUTING -p tcp --dport "$range" -j DNAT --to-destination ":$target"
        # 放行范围 (由于 PREROUTING 后进入 INPUT，需要放行目标端口，但为了稳妥，范围和目标都放行)
        iptables -A INPUT -p udp --dport "$range" -j ACCEPT
        iptables -A INPUT -p tcp --dport "$range" -j ACCEPT
        # 强制放行目标端口
        iptables -A INPUT -p udp --dport "$target" -j ACCEPT
        iptables -A INPUT -p tcp --dport "$target" -j ACCEPT
    done

    # --- 5. 封锁默认入口策略 ---
    # 最后将 INPUT 默认策略设置为 DROP，静默丢弃所有未匹配的包，不回复 RST，让扫描器认为 IP 不存在或端口超时
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    echo -e "${GREEN}✅ 隐蔽与防御规则应用成功。${RESET}"
}

# 保存规则
save_rules() {
    echo -e "\n${CYAN}[6/6] 永久保存防火墙规则...${RESET}"
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save >/dev/null 2>&1
        echo -e "${GREEN}✅ 规则已使用 netfilter-persistent 保存 (Debian/Ubuntu)。${RESET}"
    elif command -v iptables-save >/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        echo -e "${GREEN}✅ 规则已保存至 /etc/iptables/rules.v4。${RESET}"
    fi
}

main() {
    install_dependencies
    reset_firewall
    detect_ports
    configure_port_hopping
    build_firewall
    save_rules

    echo -e "\n${GREEN}==========================================${RESET}"
    echo -e "🎉 防火墙配置完毕！"
    echo -e "🛡️ 特性: 无效包静默丢弃 (防扫描) + 严格端口探测 + SSH 防爆破"
    echo -e "如果日后新增了代理节点，只需重新运行此脚本： ${CYAN}bash proxy_firewall.sh${RESET}"
    echo -e "${GREEN}==========================================${RESET}"
}

main "$@"
