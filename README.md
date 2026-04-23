# iptables 防火墙脚本 v4.5

## port.sh

代理节点防火墙管理脚本，支持：

- **Hysteria2 端口跳跃** ✅ 增强验证
- X-UI / 3x-ui / Marzban
- sing-box / xray / v2ray
- WireGuard / Trojan / TUIC / Naive

## 🆕 v4.5 新特性

### 严重问题修复
1. **H2端口跳跃死循环检测** - 防止目标端口在跳跃范围内导致DNAT死循环
2. **端口范围大小限制** - 防止过大范围导致系统性能问题（限制50000端口）
3. **Python临时文件增强** - 改进fallback逻辑，支持受限环境
4. **IPv6 DNAT地址优化** - 动态选择本机IPv6地址，提高兼容性

详见 [CHANGELOG_v4.5.md](CHANGELOG_v4.5.md)

## 特性

- IPv4 + IPv6 双栈支持
- Oracle Cloud ARM 兼容
- Docker 环境支持
- 自动检测服务端口
- SSH 防暴力破解
- 一键安装，完全自动化

## 使用方法

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

## 支持的协议

| 协议 | 端口检测 | 备注 |
|------|----------|------|
| Hysteria2 | 自动 | 支持端口跳跃 + 死循环检测 |
| X-UI | 数据库 | 需要 sqlite3 |
| sing-box | 配置文件 | JSON/YAML |
| WireGuard | 系统 | 自动检测 |
| Trojan | 配置文件 | 支持 |
| TUIC | 配置文件 | 支持 |

## 云平台兼容性

- Oracle Cloud ARM ✓
- AWS EC2 ✓
- 阿里云 ECS ✓
- 腾讯云 CVM ✓
- 任何 Linux VPS ✓

## 安全提示

⚠️ **重要**: 云平台安全组需要单独配置！

- **甲骨文云**: VCN → 安全列表 / NSG 入站规则
- **AWS**: EC2 安全组 → Inbound Rules
- **阿里云/腾讯云**: 安全组规则

本机防火墙只是第一层防护，云平台安全组必须同步放行端口。

## 端口跳跃配置示例

```bash
# 交互式添加
bash port.sh --add-hop

# 输入示例：
跳跃端口范围: 20000-50000
目标端口: 443

# ✅ 正确：目标端口443不在20000-50000范围内
# ❌ 错误：目标端口30000在20000-50000范围内（会报错）
```

## 验证端口跳跃

```bash
# 查看IPv4 NAT规则
iptables -t nat -L PREROUTING -n -v

# 查看IPv6 NAT规则
ip6tables -t nat -L PREROUTING -n -v

# 应该看到类似：
# DNAT udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpts:20000:50000 to::443
```

## 故障排查

### 端口跳跃不工作
1. 检查云平台安全组是否放行跳跃范围
2. 验证目标端口是否在OPEN_PORTS列表中：`bash port.sh --status`
3. 检查NAT规则：`iptables -t nat -L -n -v`

### IPv6不工作
1. 确认VPS支持IPv6：`ip -6 addr show`
2. 检查IPv6转发：`sysctl net.ipv6.conf.all.forwarding`
3. 查看IPv6规则：`ip6tables -L -n -v`

## 文档

- [完整审查报告](port_sh_audit.md) - 详细的代码审查和BUG分析
- [更新日志](CHANGELOG_v4.5.md) - v4.5版本修复详情

## 版本历史

- **v4.5** (2026-04-23) - 修复H2端口跳跃死循环、增强临时文件处理、优化IPv6 DNAT
- **v4.4** - 修复C1-C10系列BUG
- **v4.3** - 修复B1-B4系列BUG
- **v4.0-v4.1** - 修复A1-A14系列BUG

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License
