# port.sh

**代理节点 iptables 防火墙一键管理脚本** · v4.4

专为运行 Xray / Hysteria2 / sing-box 等代理服务的 VPS 设计。自动检测所有监听端口并生成最小权限规则集，内置 Hysteria2 端口跳跃（DNAT）、SSH 防爆破、Docker 兼容、IPv6 双栈等完整支持。

---

## 目录

- [功能特性](#功能特性)
- [支持的代理软件](#支持的代理软件)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [命令参数](#命令参数)
- [端口扫描机制](#端口扫描机制)
- [生成的防火墙规则](#生成的防火墙规则)
- [端口黑名单](#端口黑名单)
- [规则持久化](#规则持久化)
- [Docker 兼容](#docker-兼容)
- [云平台安全组提示](#云平台安全组提示)
- [常见问题](#常见问题)
- [更新日志](#更新日志)

---

## 功能特性

- **全自动端口检测** — 综合 `ss` 实时扫描、配置文件解析（JSON/JSONC/YAML）、SQLite 数据库读取，三路兜底，覆盖已运行和未运行的服务
- **Hysteria2 端口跳跃** — 自动从配置文件提取跳跃规则，或通过 `--add-hop` 手动添加；IPv4 + IPv6 DNAT 同步配置
- **SSH 防爆破** — 基于 `xt_recent` 模块，60 秒内超过 10 次连接请求自动封锁来源 IP，自动识别非标准 SSH 端口
- **最小权限原则** — INPUT/FORWARD 默认 DROP，仅放行检测到的服务端口；OUTPUT 完全放行
- **ICMPv6 NDP 保护** — 自动放行邻居发现、路由通告等 5 种必要 ICMPv6 类型，防止配置后 IPv6 断网
- **ICMP 洪泛防护** — ping 限速 5次/秒，burst 上限 10
- **规则日志** — 被拦截的连接以 `[FW-DROP]` / `[FW6-DROP]` 前缀写入系统日志，便于排查
- **Docker 自动恢复** — 检测到 Docker 运行时，规则重建后自动重启 Docker 以恢复 NAT 链
- **JSONC 注释兼容** — 内置状态机 Python 解析器，正确处理 `//` 和 `/* */` 注释（Xray/Hysteria2 广泛使用），不破坏 URL 中的 `//`
- **预览模式** — `--dry-run` 只打印将要执行的操作，不修改任何规则
- **重启持久化** — 自动通过 `netfilter-persistent` 或 systemd 服务实现开机自动恢复规则

---

## 支持的代理软件

| 软件 | 端口来源 |
|------|---------|
| Xray / V2Ray | 配置文件 `inbounds[].port` + `ss` |
| sing-box | 配置文件 `inbounds[].listen_port` + `ss` |
| Hysteria2 | 配置文件 `listen` / `portHopping` + `ss` |
| TUIC v5 | 配置文件 `server` 字段 + `ss` |
| Trojan / Trojan-Go | 配置文件 `local_port` + `ss` |
| WireGuard | `wg show` 命令 + 配置文件 `ListenPort` |
| NaïveProxy | 配置文件 + `ss` |
| Brook | 配置文件 + `ss` |
| X-UI / 3x-ui | SQLite 数据库 `inbounds` 表 + `ss` |
| Marzban | `.env` 文件 `UVICORN_PORT` + `ss` |

---

## 系统要求

- **OS**：Debian / Ubuntu / CentOS / RHEL（及其衍生版）
- **权限**：root
- **内核**：支持 `nf_conntrack`、`xt_recent`、`xt_LOG` 模块（脚本会自动 `modprobe`）
- **依赖**（缺失时自动安装）：`iptables`、`python3`、`iproute2`（提供 `ss`）、`sqlite3`（仅在检测到 X-UI 数据库时）

---

## 快速开始

```bash
# 下载
wget -O port.sh https://raw.githubusercontent.com/your-repo/port.sh/main/port.sh

# 一键配置（自动检测所有端口并应用规则）
bash port.sh

# 如果 Hysteria2 使用端口跳跃但未自动检测到，手动添加：
bash port.sh --add-hop
```

脚本执行完成后会打印完整摘要，包括开放的端口列表、跳跃规则、以及云平台安全组配置提示。

---

## 命令参数

```
bash port.sh [选项]
```

| 参数 | 说明 |
|------|------|
| （无参数） | 自动检测所有端口并配置防火墙（主流程） |
| `--dry-run` | 预览模式：打印将要开放的端口和跳跃规则，不修改 iptables |
| `--status` | 显示当前防火墙状态：开放端口、DNAT 规则、监听进程、sysctl 参数 |
| `--add-hop` | 交互式添加 Hysteria2 端口跳跃规则，并重建整个防火墙确保规则顺序正确 |
| `--reset` | 清空所有规则，恢复为全部放行（需二次确认） |
| `--help` | 显示帮助信息 |

### 使用示例

```bash
# 仅查看当前状态，不做任何修改
bash port.sh --status

# 预览将会生成哪些规则
bash port.sh --dry-run

# 手动为 Hysteria2 添加跳跃规则
bash port.sh --add-hop
# → 跳跃端口范围（如 20000-50000）: 20000-50000
# → 目标端口（代理实际监听端口，如 443）: 443

# 排查问题时查看被拦截的连接
journalctl -k --grep="FW-DROP" -f
```

---

## 端口扫描机制

脚本通过以下 6 个步骤收集需要放行的端口：

**① `ss` 实时扫描**
扫描所有公网监听端口（排除 `127.x` / `::1` 本地地址，排除 `cloudflared`、`dnsmasq`、`chronyd` 等系统服务）。

**② WireGuard**
优先通过 `wg show all listen-port` 获取，备选解析 `/etc/wireguard/*.conf` 中的 `ListenPort` 字段（覆盖 wg 进程未运行的情况）。

**③ 配置文件解析（Python）**
扫描以下目录中的 `*.json` / `*.yaml` 文件，提取 `port`、`listen_port`、`listen`、`local_port`、`server` 等字段：

```
/usr/local/etc/xray    /etc/xray          /usr/local/etc/v2ray  /etc/v2ray
/etc/sing-box          /opt/sing-box       /usr/local/etc/sing-box
/etc/hysteria          /etc/hysteria2      /usr/local/etc/hysteria{,2}
/etc/tuic              /etc/trojan{,-go}   /etc/naiveproxy
/etc/brook             /etc/x-ui           /opt/3x-ui
/opt/marzban           /etc/amnezia{wg}    /etc/gost
```

**④ X-UI / 3x-ui SQLite 数据库**
直接读取 `inbounds` 表中 `enable=1` 的节点端口，无需服务处于运行状态。

**⑤ Marzban `.env`**
读取 `UVICORN_PORT` 变量（兼容等号两侧有空格的格式）。

**⑥ 233boy xray 文件名约定**
`/etc/xray/conf/*.json` 中以端口号为文件名前缀的配置文件（如 `443.json`）。

最终 `80` 和 `443` 端口始终强制加入放行列表。

---

## 生成的防火墙规则

执行主流程后生成的规则集顺序如下（IPv4，IPv6 同步）：

```
INPUT   默认策略: DROP
FORWARD 默认策略: DROP
OUTPUT  默认策略: ACCEPT

INPUT  lo               → ACCEPT          # 本地回环
INPUT  ESTABLISHED,RELATED → ACCEPT       # 已建立连接的回程包
INPUT  icmp echo-request (≤5/s) → ACCEPT  # ping 限速放行
INPUT  icmp             → DROP            # 其余 ICMP 全部拦截

INPUT  tcp SSH_PORT --set SSH_BF          # 记录 SSH 连接来源
INPUT  tcp SSH_PORT --hitcount 10 / 60s → DROP  # 超频则封锁
INPUT  tcp SSH_PORT     → ACCEPT          # 正常 SSH 放行

INPUT  tcp/udp PORT_1   → ACCEPT          # 检测到的服务端口
INPUT  tcp/udp PORT_2   → ACCEPT
...（每个开放端口各一条 TCP + 一条 UDP）

FORWARD ESTABLISHED,RELATED → ACCEPT     # NAT 回程包（端口跳跃必需）

NAT PREROUTING udp dport S:E → DNAT :T  # 端口跳跃（Hysteria2）
NAT PREROUTING tcp dport S:E → DNAT :T
INPUT  tcp/udp dport T  → ACCEPT          # DNAT 后目标端口放行

INPUT  limit 5/min → LOG [FW-DROP]        # 限速日志
INPUT  → DROP                             # 兜底拦截
```

> **关于端口跳跃的 iptables 处理链顺序**
> DNAT 在 `PREROUTING` 阶段执行，将外部端口范围 `S:E` 的目标端口改写为实际监听端口 `T`。进入 `filter INPUT` 链时数据包的目标端口已经是 `T`，因此 INPUT ACCEPT 规则必须针对端口 `T` 而非范围 `S:E`。

---

## 端口黑名单

以下端口即使检测到监听也**不会**被放行（保护数据库和危险服务）：

| 类别 | 端口 |
|------|------|
| 危险/系统协议 | 23 25 53 69 111 135 137-139 445 514 631 |
| 邮件协议 | 110 143 465 587 993 995 |
| 数据库 | 1433 1521 3306 5432 6379 27017 |
| 远程桌面 / NFS | 3389 5900-5902 2049 |
| 系统协议 | 323（RPKI-RTR） |
| 233boy 内部端口 | 10080–10086 |

> SSH 端口单独处理（含防爆破规则），不受此黑名单影响。
> 面板管理端口（54321、2053 等）**不在黑名单中**——如果面板正在运行，ss 会检测到并自动放行；如果未运行则不放行，这是预期行为。建议通过 SSH 隧道访问面板。

---

## 规则持久化

脚本执行后自动将规则持久化，确保重启后自动恢复：

- **Debian / Ubuntu**（检测到 `netfilter-persistent`）：调用 `netfilter-persistent save`，规则写入 `/etc/iptables/rules.v4` 和 `/etc/iptables/rules.v6`
- **其他发行版**：创建 `/etc/systemd/system/iptables-restore.service`，在网络启动前（`Before=network-pre.target`）自动执行 `iptables-restore`

同时写入 `/etc/sysctl.d/98-port-firewall.conf` 持久化以下内核参数：

```
net.ipv4.ip_forward = 1           # 端口跳跃 NAT 必需
net.ipv6.conf.all.forwarding = 1  # IPv6 端口跳跃必需
net.ipv4.conf.all.rp_filter = 2   # 宽松模式，防止 UDP 转发包被丢弃
net.ipv4.tcp_timestamps = 0       # 防信息泄露
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
```

---

## Docker 兼容

iptables 规则重建（flush）会清空 NAT 表，导致 Docker 的 Bridge 网络端口映射失效。脚本在以下两个场景均做了处理：

- **主流程** / **`--add-hop`**：`flush_rules` 执行前检测 Docker 运行状态，规则全部应用完毕后自动 `systemctl restart docker` 重建网络链
- **`--reset`**：清空规则后同样自动重启 Docker

---

## 云平台安全组提示

iptables 只控制操作系统层面的防火墙。大多数云平台在 VM 外层还有独立的安全组，**两者必须同时放行端口，流量才能到达服务**。

| 平台 | 配置位置 |
|------|---------|
| Oracle Cloud | VCN → 安全列表 / NSG → 入站规则 |
| AWS | EC2 → 安全组 → Inbound Rules |
| 阿里云 | ECS → 安全组规则 |
| 腾讯云 | CVM → 安全组 → 入站规则 |
| GCP | VPC → 防火墙规则 |

---

## 常见问题

**Q: 运行后 SSH 断了怎么办？**

脚本在修改规则前会检测 SSH 端口（`ss` + `sshd_config`）并自动放行，正常情况不会断开。如果意外断开，通过云平台的 VNC/串口控制台登录，执行 `bash port.sh --reset` 清空规则后重新配置。

**Q: 为什么 X-UI 面板 54321 端口没有被放行？**

出于安全考虑，面板管理端口建议只通过 SSH 隧道访问，不应直接对公网暴露：

```bash
# 本地执行，然后访问 http://127.0.0.1:54321
ssh -L 54321:127.0.0.1:54321 root@your-server-ip
```

**Q: Hysteria2 端口跳跃配置了但不通？**

1. 确认云平台安全组已放行跳跃端口范围（如 20000-50000 UDP）
2. 运行 `bash port.sh --status` 确认 DNAT 规则已生成
3. 检查 Hysteria2 客户端配置中跳跃端口范围与服务端一致

**Q: 容器环境（LXC/OpenVZ）运行报错？**

部分容器环境不允许加载内核模块或修改 iptables。脚本对所有 `modprobe` 和 `sysctl` 操作都加了 `|| true`，即使失败也不会中断，但 `-m conntrack`、`-m recent` 规则可能不生效。请在宿主机层面配置防火墙，或联系 VPS 提供商开启相应权限。

**Q: 重启后规则丢失？**

检查持久化服务状态：

```bash
# systemd 方式
systemctl status iptables-restore.service

# iptables-persistent 方式
systemctl status netfilter-persistent

# 手动恢复
iptables-restore < /etc/iptables/rules.v4
ip6tables-restore < /etc/iptables/rules.v6
```

**Q: 如何查看被防火墙拦截的连接？**

```bash
# 实时监控
journalctl -k -f --grep="FW.DROP"

# 查看历史
dmesg | grep "FW-DROP"
```

---

## 更新日志

### v4.4
- **[C1] 修复端口跳跃 INPUT 规则架构 Bug**：DNAT 后 filter INPUT 看到的是目标端口 `T` 而非跳跃范围，原 `--dport S:E` 规则是死代码
- **[C2] 修复 Hysteria2 跳跃目标端口未加入 OPEN_PORTS**：服务未运行时目标端口缺失 ACCEPT 导致 DNAT 包被 DROP
- **[C3] 修复 `--add-hop` 规则追加在 DROP 之后**：改为重建完整防火墙确保规则顺序
- **[C4] 修复 `--reset` 清空 NAT 表后 Docker 断网**：重置后自动重启 Docker
- **[C5]** `mktemp` 加 fallback，磁盘满或权限受限时不 abort
- **[C6]** 配置文件列表去重，避免同一文件被 Python 解析两次
- **[C7]** IPv6 DROP 前补 `[FW6-DROP]` LOG 规则，与 IPv4 对称
- **[C8]** 修正注释：323 是 RPKI-RTR 端口，非 NTP
- **[C9] 预加载内核模块**：最小化 VPS / LXC 下 `modprobe nf_conntrack xt_recent` 等，防止规则静默失效
- **[C10]** `detect_existing_hop_rules` 同时读取 IPv6 iptables

### v4.3
- **[A12]** `systemctl try-restart` → `restart`，首次运行及 failed 状态均可正确拉起
- `add_port` 去重改用 glob 通配符替代 `=~` 正则
- `sysctl --system` 重载所有配置目录

### v4.0 – v4.2
- IPv6 DNAT 语法修复（`[::]:PORT`）、SSH 检测正则、Docker NAT 恢复、JSONC 注释解析、Marzban 端口提取、FORWARD 链安全漏洞修复等

---

## License

MIT
