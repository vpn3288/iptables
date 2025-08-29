# iptables
# 基本使用
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh)

# 预演模式
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --dry-run

# 查看状态
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --status

# 添加端口跳跃
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --add-range
