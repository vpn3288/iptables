# iptables 防火墙脚本

## port.sh

代理节点防火墙管理脚本，支持：

- Hysteria2 端口跳跃
- X-UI / 3x-ui / Marzban
- sing-box / xray / v2ray
- WireGuard / Trojan / TUIC / Naive

### 特性

- IPv4 + IPv6 双栈支持
- Oracle Cloud ARM 兼容
- Docker 环境支持
- 自动检测服务端口
- SSH 防暴力破解
- 一键安装，完全自动化

### 使用方法

```bash
# 一键安装
bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/iptables/main/port.sh)

# 查看状态
bash port.sh --status

# 重置防火墙
bash port.sh --reset

# 添加端口跳跃
bash port.sh --add-hop
```

### 支持的协议

| 协议 | 端口检测 | 备注 |
|------|----------|------|
| Hysteria2 | 自动 | 支持端口跳跃 |
| X-UI | 数据库 | 需要 sqlite3 |
| sing-box | 配置文件 | JSON/YAML |
| WireGuard | 系统 | 自动检测 |
| Trojan | 配置文件 | 支持 |
| TUIC | 配置文件 | 支持 |

### 云平台兼容性

- Oracle Cloud ARM ✓
- AWS EC2 ✓
- 阿里云 ECS ✓
- 腾讯云 CVM ✓
- 任何 Linux VPS ✓
