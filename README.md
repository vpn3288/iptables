# iptables
# 基本使用
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh)

# 预演模式
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --dry-run

# 查看状态
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --status

# 添加端口跳跃
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --add-range

# 查看防火墙当前状态
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/iptables/refs/heads/main/port.sh) --status
# 代理节点防火墙管理脚本 v3.6

> 代理节点专用 iptables 防火墙脚本。自动扫描代理软件监听端口并配置规则，支持端口跳跃、SSH 防暴力破解、规则持久化，与 BBRplus 和 youhua.sh 完全兼容。


## 兼容性

| 项目 | 说明 |
|---|---|
| 系统 | Ubuntu 20.04 / 22.04 / 24.04、Debian 11 / 12 / 13 |
| 虚拟化 | KVM ✅　OpenVZ / LXC ⚠️（iptables 支持取决于宿主机） |
| 架构 | x86_64 |
| 权限 | 需要 root |
| BBRplus | ✅ 完全兼容 |
| youhua.sh | ✅ 完全兼容（sysctl 写入独立文件，不互相覆盖） |

---

## 推荐运行顺序

```
第 1 步：安装 BBRplus → 重启
第 2 步：运行 youhua.sh → 系统优化
第 3 步：运行本脚本   → 防火墙配置（最后运行）
```

---

## 功能说明

### 1. 端口自动检测

以 `ss` 实际监听状态为权威来源，配置文件作为补充（覆盖未运行节点的端口）：

- **ss 扫描**：读取当前系统真实监听的公网端口，过滤掉 localhost 绑定的内部端口
- **配置文件解析**：用 Python3 解析 JSON 配置，支持所有主流代理软件格式
- **文件名兜底**：兼容 233boy 脚本的 `VLESS-Reality-12503.json` 文件名端口格式

**支持自动识别的代理软件：**

| 软件 | 配置路径 |
|---|---|
| Xray | `/usr/local/etc/xray`、`/etc/xray` |
| V2Ray | `/usr/local/etc/v2ray`、`/etc/v2ray` |
| Sing-box | `/etc/sing-box`、`/usr/local/etc/sing-box` |
| Hysteria / Hysteria2 | `/etc/hysteria`、`/etc/hysteria2` |
| Trojan | `/etc/trojan` |
| TUIC | `/etc/tuic` |
| 3x-ui / x-ui | `/opt/3x-ui/bin`、`/usr/local/x-ui/bin` |

80 和 443 端口默认始终开放。

---

### 2. 自动屏蔽高危端口

以下端口即使被检测到也不会开放：

| 类别 | 端口 |
|---|---|
| 高危协议 | 23、25、53、69、111、514、631 |
| Windows 共享 | 135、137、138、139、445 |
| 邮件 | 110、143、465、587、993、995 |
| 数据库 | 1433、1521、3306、5432、6379、27017 |
| 远程桌面 | 3389、5900 ~ 5902 |
| 其他高危 | 2049、323、8181、9090、54321 等 |

---

### 3. SSH 防暴力破解

60 秒内登录失败超过 6 次，自动封锁该 IP。SSH 端口自动检测（读取 `ss` 和 `sshd_config`，默认 22）。

---

### 4. 端口跳跃（Port Hopping）

Hysteria2 的端口跳跃可以绕过运营商的 QoS 限速，脚本支持自动检测和手动添加：

**自动检测 Hysteria2 跳跃配置：**

脚本启动时自动读取 `/etc/hysteria2/config.yaml`（或 json），识别 `portHopping` 字段，无需手动配置。

**手动添加跳跃规则：**

```bash
bash port.sh --add-hop
```

按提示输入端口范围（如 `20000-50000`）和目标端口（代理实际监听的端口），脚本自动配置 NAT DNAT 规则。

---

### 5. 规则持久化

- 规则保存到 `/etc/iptables/rules.v4`
- 优先使用 `netfilter-persistent` 保存
- 无 netfilter-persistent 时自动创建 `iptables-restore.service` systemd 服务，重启后自动还原

---

### 6. sysctl 安全加固

写入独立文件 `/etc/sysctl.d/98-port-firewall.conf`，不覆盖其他脚本的配置：

| 参数 | 值 | 说明 |
|---|---|---|
| `net.ipv4.ip_forward` | 1 | 端口跳跃 NAT 必须 |
| `net.ipv4.conf.all.send_redirects` | 0 | 禁止发送 ICMP 重定向 |
| `net.ipv4.conf.all.accept_redirects` | 0 | 禁止接受 ICMP 重定向 |
| `net.ipv4.conf.all.accept_source_route` | 0 | 禁止源路由 |
| `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | 忽略广播 ping |
| `net.ipv4.tcp_timestamps` | 0 | 防信息泄露，与 youhua.sh 一致 |
| `net.ipv4.conf.all.rp_filter` | 2 | 宽松模式，兼容端口跳跃 NAT |

---

## 日常管理命令

```bash
# 查看当前状态（开放端口 / NAT 跳跃规则 / 关键 sysctl 参数）
bash port.sh --status

# 手动添加端口跳跃规则
bash port.sh --add-hop

# 重置防火墙为全部放行（紧急恢复用）
bash port.sh --reset

# 预览检测结果（不实际修改）
bash port.sh --dry-run

# 查看帮助
bash port.sh --help
```

**直接查看 iptables 规则：**

```bash
# 查看 INPUT 规则
iptables -L -n -v

# 查看 NAT 端口跳跃规则
iptables -t nat -L -n -v
```

---

## 写入的文件清单

| 文件 | 内容 |
|---|---|
| `/etc/iptables/rules.v4` | iptables 规则持久化 |
| `/etc/sysctl.d/98-port-firewall.conf` | ip_forward、rp_filter、tcp_timestamps 等安全参数 |
| `/etc/systemd/system/iptables-restore.service` | 开机自动还原规则（无 netfilter-persistent 时创建） |

---

## 常见问题

**Q：配置完防火墙后 SSH 断连**

在 VPS 控制台（VNC / Console）登录后执行：
```bash
iptables -P INPUT ACCEPT && iptables -F
```
或运行重置命令：
```bash
bash port.sh --reset
```
重置后重新运行脚本，下次运行前先用 `--dry-run` 预览确认 SSH 端口已被检测到。

---

**Q：端口跳跃不生效，UDP 包丢失**

检查 `rp_filter` 的值：
```bash
sysctl net.ipv4.conf.all.rp_filter
```
值必须为 `2`（宽松模式），值为 `1` 时会丢弃跳跃端口的 UDP 转发包。手动修复：
```bash
sysctl -w net.ipv4.conf.all.rp_filter=2
```
重新运行本脚本后该值会自动写入并持久化。

---

**Q：代理端口没有被自动检测到**

代理软件可能未运行，或配置文件格式不标准。手动查看当前监听端口：
```bash
ss -tulpn | grep -v 127
```
确认端口后，可以修改代理配置文件的 `listen` 字段去掉 `127.0.0.1` 绑定，重启代理后再次运行本脚本。

---

**Q：如何更新规则（新增了代理协议）**

重新运行脚本即可，会自动扫描最新的监听端口并重建规则：
```bash
bash port.sh
```

---

## 版本历史

| 版本 | 更新内容 |
|---|---|
| **v3.6** | `rp_filter=2` 宽松模式，sysctl 写入独立文件 `/etc/sysctl.d/98-port-firewall.conf`，`--status` 新增关键参数显示，完全兼容 youhua.sh v2.4+ 和 BBRplus |
| v3.5 | 初始版本：自动端口扫描、配置文件解析、端口跳跃、SSH 防暴力破解、规则持久化 |
