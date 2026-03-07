#!/bin/bash
# port.sh v4.0 — 代理节点防火墙管理脚本
# 支持: Hysteria2端口跳跃 | X-UI/3x-ui/Marzban | sing-box | xray | v2ray | WireGuard | Trojan | TUIC | Naive
# 兼容: Oracle Cloud ARM | 各大 VPS | Docker 环境 | IPv6 双栈
#
# ═══════════════════ 修复清单（相对 v3.6）═══════════════════
# [BUG1]  get_public_ports: 删除 <32768 过滤，代理端口大量在高位
# [BUG2]  EXCLUDE_PROCS: systemd.resolve → systemd-resolve（进程名错误）
# [BUG3]  parse_hop: 改用 bash 参数展开，更健壮
# [BUG4]  detect_existing_hop_rules: to::[PORT] 正则扩展为兼容 to:IP:PORT
# [BUG5]  detect_hysteria_hop: YAML listen 用 awk 兼容 ":443" 和 "443" 两种格式
# [BUG6]  detect_hysteria_hop: JSON listen 正则简化，补 listen_port 字段
# [BUG7]  detect_hysteria_hop: 补充 /usr/local/etc/hysteria2、server.yaml 等路径
# [BUG8]  detect_hysteria_hop: 无跳跃但有监听端口时，自动 add_port
# [BUG9]  FORWARD --ctstate DNAT 是无效 conntrack 状态（应为 --ctstatus），
#         修正为 NEW + ESTABLISHED,RELATED，保证 NAT 转发正常
# [BUG10] flush_rules: 检测 Docker，清空规则后自动重启 Docker 重建网络
# [BUG11] 新增 ip6tables IPv6 完整规则（甲骨文云强依赖）
# [BUG12] install_deps: 自动停用 firewalld / ufw，防止规则被覆盖
# [BUG13] SSH hitcount 6 → 10，避免多路复用 SSH 终端被误封
# [BUG14] iptables-restore.service: 用 command -v 动态查路径，非硬编码 /sbin/
# [BUG15] Python 解析器: 新增 YAML 支持 + Trojan/TUIC/Hysteria2/Naive 格式
# [BUG16] detect_ports: 新增 X-UI SQLite 读取 + Marzban 路径 + WireGuard
# [BUG17] 新增甲骨文云 VCN 安全组提示
# [BUG18] 空数组 ${arr[@]} 在 set -u 下的安全防护
# ════════════════════════════════════════════════════════════

set -uo pipefail

# ── 颜色 & 工具函数 ──────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠  $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

SSH_PORT="" OPEN_PORTS=() HOP_RULES=() VERSION="4.0" DRY_RUN=false
_status=0 _reset=0 _addhop=0
_DOCKER_RUNNING=0   # 记录 Docker 是否在运行，用于清空规则后重启

for arg in "$@"; do case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --status)  _status=1 ;;
    --reset)   _reset=1 ;;
    --add-hop) _addhop=1 ;;
    --help|-h)
        echo "用法: bash port.sh [选项]"
        echo "  （无参数）    自动检测并配置防火墙"
        echo "  --dry-run     预览模式，不实际修改规则"
        echo "  --status      显示当前防火墙状态"
        echo "  --reset       清除所有规则（全部放行）"
        echo "  --add-hop     手动添加 Hysteria2 端口跳跃规则"
        echo "  --help        显示帮助"
        exit 0 ;;
    *) err "未知参数: $arg（用 --help 查看用法）" ;;
esac; done

# [BUG2 FIX] 进程名 systemd.resolve → systemd-resolve
EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|systemd\.resolve|named|unbound|ntpd|avahi|NetworkManager"

# ============================================================
# get_public_ports: ss 扫描公网监听端口
# [BUG1 FIX] 删除 <32768 过滤，代理端口大量在 30000-65535 区间
# ============================================================
get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | sort -un || true
}

# ============================================================
# install_deps: 安装依赖、配置 sysctl、处理防火墙前端冲突
# ============================================================
install_deps() {
    local pkgs=()
    command -v iptables  &>/dev/null || pkgs+=(iptables)
    command -v ss        &>/dev/null || pkgs+=(iproute2)
    # ip6tables 一般随 iptables 一起安装，但不同发行版包名不同
    if ! command -v ip6tables &>/dev/null; then
        command -v apt-get &>/dev/null && pkgs+=(ip6tables) || true
    fi
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        command -v apt-get &>/dev/null \
            && apt-get update -qq && apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || true
        command -v yum &>/dev/null \
            && yum install -y -q "${pkgs[@]}" 2>/dev/null || true
        command -v dnf &>/dev/null \
            && dnf install -y -q "${pkgs[@]}" 2>/dev/null || true
    fi

    # [BUG12 FIX] 禁用 firewalld / ufw，防止与 iptables 规则打架
    # Oracle Linux 默认启用 firewalld，Ubuntu 可能有 ufw
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        warn "检测到 firewalld 正在运行，停止并禁用以避免规则冲突..."
        systemctl disable --now firewalld 2>/dev/null || true
        ok "firewalld 已禁用"
    fi
    if systemctl is-active --quiet ufw 2>/dev/null; then
        warn "检测到 ufw 正在运行，停止并禁用以避免规则冲突..."
        ufw --force disable 2>/dev/null || true
        systemctl disable --now ufw 2>/dev/null || true
        ok "ufw 已禁用"
    fi

    # ── IPv4 转发（端口跳跃 NAT 必须）──────────────────────────
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null

    # ── IPv6 转发（甲骨文 ARM 双栈、IPv6 跳跃必须）────────────
    sysctl -w net.ipv6.conf.all.forwarding=1  &>/dev/null || true
    sysctl -w net.ipv6.conf.default.forwarding=1 &>/dev/null || true

    # ── 安全加固（不覆盖 youhua.sh 的性能参数）────────────────
    sysctl -w net.ipv4.conf.all.send_redirects=0      &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0    &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true

    # ── tcp_timestamps=0：防信息泄露，与 youhua.sh v2.4 一致 ──
    sysctl -w net.ipv4.tcp_timestamps=0 &>/dev/null || true

    # ── rp_filter=2 宽松模式：与 youhua.sh v2.4 一致 ──────────
    # =1 严格模式会丢弃端口跳跃的 UDP 转发包导致跳跃失效
    # =2 保留路径过滤安全性，允许 NAT 转发包通过
    sysctl -w net.ipv4.conf.all.rp_filter=2     &>/dev/null || true
    sysctl -w net.ipv4.conf.default.rp_filter=2 &>/dev/null || true

    # 持久化到独立文件，不污染其他脚本写入的 sysctl.conf
    cat > /etc/sysctl.d/98-port-firewall.conf << 'EOF'
# port.sh v4.0 写入 — 与 youhua.sh v2.4 / BBRplus 完全兼容
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
# tcp_timestamps=0：防信息泄露，与 youhua.sh v2.4 一致
net.ipv4.tcp_timestamps=0
# rp_filter=2：宽松反向路径过滤，兼容端口跳跃 NAT
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-port-firewall.conf &>/dev/null || true
    ok "sysctl 参数已写入 /etc/sysctl.d/98-port-firewall.conf"
}

# ============================================================
# detect_ssh: 检测 SSH 端口
# ============================================================
detect_ssh() {
    # 优先从 ss 实时监听状态获取
    SSH_PORT=$(ss -tlnp 2>/dev/null \
        | grep -E '\bsshd?\b' \
        | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
    # 备选：读取 sshd 配置文件
    [[ -z "$SSH_PORT" ]] && \
        SSH_PORT=$(grep -E '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1)
    # 最终默认值
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ============================================================
# parse_hop: 解析跳跃规则字符串 "20000-50000->443"
# [BUG3 FIX] 改用 bash 参数展开，比 cut+tr 管道更可靠
# ============================================================
parse_hop() {
    local rule=$1
    HOP_S="${rule%%-*}"             # "20000-50000->443" → "20000"
    local _rest="${rule#*-}"        # → "50000->443"
    HOP_E="${_rest%%->*}"           # → "50000"
    HOP_T="${rule##*>}"             # → "443"
}

# ============================================================
# port_in_hop_range: 检查端口是否落在跳跃范围内
# [BUG18 FIX] 安全处理空数组
# ============================================================
port_in_hop_range() {
    local p=$1
    [[ ${#HOP_RULES[@]} -eq 0 ]] && return 1
    local rule
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ -n "${HOP_S:-}" && -n "${HOP_E:-}" ]] || continue
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

# ============================================================
# is_blacklisted: 不对外开放的系统/危险/面板管理端口
# 注意: 8000/8001 已从黑名单移除（naive proxy 默认监听这些端口）
# ============================================================
is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    case "$p" in
        # 危险/系统协议端口
        23|25|53|69|111|135|137|138|139|445|514|631) return 0 ;;
        # 邮件协议
        110|143|465|587|993|995) return 0 ;;
        # 数据库
        1433|1521|3306|5432|6379|27017) return 0 ;;
        # 远程桌面 / NFS / 时间
        3389|5900|5901|5902|323|2049) return 0 ;;
        # 面板 UI 管理端口（不应对外暴露，应通过 SSH 隧道访问）
        # X-UI: 54321, 3x-ui: 2053/2096/2087, Marzban: 8000(docker) 使用 8080 映射
        54321|62789|2053|2087|2096) return 0 ;;
        # 常见 Web 管理界面（非代理服务端口）
        8181|9090|3000|3001) return 0 ;;
        # 233boy xray 内部端口段
        10080|10081|10082|10083|10084|10085|10086) return 0 ;;
    esac
    return 1
}

# ============================================================
# add_port: 将端口加入开放列表（带校验和去重）
# [BUG18 FIX] 安全处理空数组
# ============================================================
add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]              || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                  && return 0
    port_in_hop_range "$p"              && return 0
    # 去重检查（空数组安全）
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        [[ " ${OPEN_PORTS[*]} " =~ " $p " ]] && return 0
    fi
    OPEN_PORTS+=("$p")
}

# ============================================================
# detect_existing_hop_rules: 从当前 iptables NAT 读取已有跳跃规则
# [BUG4 FIX] 正则兼容 to::PORT（无 IP）和 to:IP:PORT（有 IP）两种格式
# ============================================================
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' \
            | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        # 兼容 iptables 显示的两种格式:
        #   to::443             （DNAT --to-destination :443）
        #   to:0.0.0.0:443     （DNAT --to-destination 0.0.0.0:443）
        #   to:192.168.1.1:443 （DNAT 到其他主机）
        target=$(echo "$line" \
            | grep -oE 'to:(:[0-9]+|[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+)' \
            | grep -oE '[0-9]+$')
        [[ -n "$range" && -n "$target" ]] || continue
        local rule="${range}->${target}"
        if [[ ${#HOP_RULES[@]} -eq 0 ]] || \
           [[ ! " ${HOP_RULES[*]} " =~ " ${rule} " ]]; then
            HOP_RULES+=("$rule")
            info "读取已有跳跃规则: ${range/-/:} → $target"
        fi
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
}

# ============================================================
# detect_hysteria_hop: 从 Hysteria2 配置文件检测端口跳跃
# [BUG5 FIX] YAML: 用 awk 兼容 "listen: :443" 和 "listen: 443"
# [BUG6 FIX] JSON: 正则简化 + 补 listen_port 字段
# [BUG7 FIX] 补充更多路径和文件名
# [BUG8 FIX] 无跳跃但有 listen 端口时，自动加入开放列表
# ============================================================
detect_hysteria_hop() {
    local dirs=(
        /etc/hysteria
        /etc/hysteria2
        /usr/local/etc/hysteria
        /usr/local/etc/hysteria2
    )
    local file_names=(config server)

    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for fname in "${file_names[@]}"; do
            for ext in json yaml yml; do
                local f="${d}/${fname}.${ext}"
                [[ -f "$f" ]] || continue
                local listen_port="" hop_range=""

                if [[ "$ext" == "json" ]]; then
                    # [BUG6 FIX] 兼容:
                    #   "listen": ":443"           → listen 字段 + 冒号前缀
                    #   "listen": "0.0.0.0:443"    → listen 字段 + IP 前缀
                    #   "listen_port": 443         → listen_port 数字字段
                    listen_port=$(python3 - "$f" 2>/dev/null << 'PYEOF'
import json, sys, re
try:
    with open(sys.argv[1]) as fp:
        d = json.load(fp)
    # Hysteria2 JSON: listen 字段
    v = d.get('listen','')
    if v:
        m = re.search(r':(\d+)$', v)
        if m: print(m.group(1)); exit()
    # listen_port 数字字段（部分版本）
    lp = d.get('listen_port')
    if isinstance(lp, int) and 1 <= lp <= 65535:
        print(lp)
except Exception: pass
PYEOF
                    )
                    hop_range=$(grep -oE \
                        '"(portHopping|portRange|hop)"\s*:\s*"[0-9]+-[0-9]+"' \
                        "$f" 2>/dev/null \
                        | grep -oE '[0-9]+-[0-9]+' | head -1)

                else
                    # [BUG5 FIX] YAML: 用 awk 从 "listen: :443" 或 "listen: 443" 均能提取
                    # 原 grep -oE ':[0-9]+' 在 "listen: 443"（无冒号前缀）时失效
                    listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                        | awk -F: '{
                            # 最后一个冒号后面的数字（处理 ":PORT" 格式）
                            for(i=NF;i>=1;i--) {
                                gsub(/[^0-9]/,"",$i)
                                if($i~/^[0-9]+$/ && $i+0>=1 && $i+0<=65535) {
                                    print $i; exit
                                }
                            }
                          }' | head -1)
                    hop_range=$(grep -E \
                        '^\s*(portHopping|portRange|hop)\s*:' \
                        "$f" 2>/dev/null \
                        | grep -oE '[0-9]+-[0-9]+' | head -1)
                fi

                if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                    local rule="${hop_range}->${listen_port}"
                    local already=0
                    [[ ${#HOP_RULES[@]} -gt 0 ]] && \
                        [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] && already=1
                    if [[ $already -eq 0 ]]; then
                        HOP_RULES+=("$rule")
                        ok "检测到 Hysteria2 端口跳跃 ($f): $hop_range → $listen_port"
                    fi
                elif [[ -n "$listen_port" ]]; then
                    # [BUG8 FIX] 有监听端口但无跳跃配置时，确保端口被放行
                    add_port "$listen_port"
                    info "Hysteria2 固定监听端口 ($f): $listen_port"
                fi
            done
        done
    done
}

# ============================================================
# detect_ports: 综合端口扫描（ss + 配置文件 + 数据库）
# ============================================================
detect_ports() {
    info "扫描公网监听端口..."

    # ── 1. ss 实时扫描（最可靠）──────────────────────────────
    while read -r port; do
        add_port "$port"
    done < <(get_public_ports)

    # ── 2. WireGuard 端口检测 ─────────────────────────────────
    # [BUG16 FIX] 新增 WireGuard 支持
    if command -v wg &>/dev/null; then
        while IFS= read -r line; do
            local wg_port
            wg_port=$(echo "$line" | awk '{print $2}')
            [[ "$wg_port" =~ ^[0-9]+$ ]] && add_port "$wg_port"
        done < <(wg show all listen-port 2>/dev/null || true)
    fi
    for wg_conf in /etc/wireguard/*.conf /usr/local/etc/wireguard/*.conf; do
        [[ -f "$wg_conf" ]] || continue
        local wg_port
        wg_port=$(grep -E '^[[:space:]]*ListenPort[[:space:]]*=' "$wg_conf" \
            | grep -oE '[0-9]+' | head -1)
        [[ -n "$wg_port" ]] && add_port "$wg_port" && \
            info "WireGuard 配置端口 ($wg_conf): $wg_port"
    done

    # ── 3. 配置文件补充（覆盖未运行节点的端口）──────────────
    # [BUG15 FIX] Python 解析器：新增 YAML / Trojan / TUIC / Hysteria2 / Naive 格式
    local py_parser="/tmp/_fw_parse_ports_v4.py"
    cat > "$py_parser" << 'PYEOF'
import json, sys, re, os

# 尝试导入 YAML 支持
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def parse_addr_port(v):
    """从各种地址格式提取端口: ':443' / '0.0.0.0:443' / '443' / 443"""
    if v is None: return None
    if isinstance(v, int): return v if 1 <= v <= 65535 else None
    s = str(v).strip()
    if s.isdigit():
        p = int(s); return p if 1 <= p <= 65535 else None
    m = re.search(r':(\d+)$', s)
    if m:
        p = int(m.group(1)); return p if 1 <= p <= 65535 else None
    return None

def is_local_bind(v):
    """判断是否只绑定本地（排除 127.x / ::1 / localhost）"""
    s = str(v or '').strip()
    return s.startswith('127.') or s == '::1' or s == 'localhost'

def extract_json(data):
    ports = []

    # ── V2Ray / Xray / sing-box: inbounds[].port / listen_port ──
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        if is_local_bind(inb.get('listen', '')): continue
        for key in ('port', 'listen_port'):
            p = parse_addr_port(inb.get(key))
            if p: ports.append(p)

    # ── V2Ray 旧格式: inbound / inboundDetour ─────────────────
    for src in ([data.get('inbound')] + list(data.get('inboundDetour') or [])):
        if not isinstance(src, dict): continue
        if is_local_bind(src.get('listen', '')): continue
        p = parse_addr_port(src.get('port'))
        if p: ports.append(p)

    # ── Trojan: local_port ────────────────────────────────────
    p = parse_addr_port(data.get('local_port'))
    if p: ports.append(p)

    # ── Hysteria2 / TUIC / Naive: listen / server ────────────
    for key in ('listen', 'server', 'listen_addr'):
        v = data.get(key)
        if isinstance(v, str) and not is_local_bind(v):
            p = parse_addr_port(v)
            if p: ports.append(p)

    # ── TUIC v5: server: "0.0.0.0:443" ──────────────────────
    server = data.get('server', '')
    if isinstance(server, str):
        p = parse_addr_port(server)
        if p and not is_local_bind(server): ports.append(p)

    return sorted(set(ports))

def extract_yaml(data):
    """YAML 格式 (Hysteria2 / Clash / sing-box YAML)"""
    if not isinstance(data, dict): return []
    ports = []

    # Hysteria2 YAML: listen / server
    for key in ('listen', 'server', 'listen_addr'):
        v = data.get(key)
        p = parse_addr_port(v)
        if p and not is_local_bind(str(v or '')): ports.append(p)

    # sing-box YAML inbounds (不常见但兼容)
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('listen_port', 'port'):
            p = parse_addr_port(inb.get(key))
            if p: ports.append(p)

    return sorted(set(ports))

for f in sys.argv[1:]:
    try:
        ext = os.path.splitext(f)[1].lower()
        with open(f, encoding='utf-8', errors='ignore') as fp:
            content = fp.read()
        if ext in ('.yaml', '.yml') and HAS_YAML:
            data = yaml.safe_load(content)
            for p in extract_yaml(data): print(p)
        else:
            # 非 JSON 格式会抛异常，被 except 静默忽略
            data = json.loads(content)
            for p in extract_json(data): print(p)
    except Exception:
        pass
PYEOF

    local cfg_files=()
    local cfg_dirs=(
        # Xray / V2Ray
        /usr/local/etc/xray  /etc/xray
        /usr/local/etc/v2ray /etc/v2ray
        # sing-box
        /etc/sing-box /opt/sing-box /usr/local/etc/sing-box
        # Hysteria2（目录已在 detect_hysteria_hop 覆盖，但仍保留以防其他文件名）
        /etc/hysteria /etc/hysteria2
        /usr/local/etc/hysteria /usr/local/etc/hysteria2
        # TUIC
        /etc/tuic /usr/local/etc/tuic
        # Trojan / Trojan-Go
        /etc/trojan /etc/trojan-go /usr/local/etc/trojan /usr/local/etc/trojan-go
        # Naive proxy
        /etc/naiveproxy /usr/local/etc/naive /usr/local/etc/naiveproxy
        # Brook
        /etc/brook /usr/local/etc/brook
        # X-UI / 3x-ui / Marzban（JSON 侧配置）
        /etc/x-ui /usr/local/x-ui/bin
        /opt/3x-ui /opt/3x-ui/bin
        /opt/marzban
        # AmneziaWG / VLESS 面板
        /etc/amnezia /etc/amneziawg
        # Gost
        /etc/gost /usr/local/etc/gost
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for pat in "config.json" "config.yaml" "config.yml" \
                   "server.json" "server.yaml" "server.yml" \
                   "*.json" "conf/*.json" "confs/*.json"; do
            for f in "${d}"/${pat}; do
                [[ -f "$f" ]] && cfg_files+=("$f")
            done
        done
    done
    # Marzban Xray 配置（默认路径）
    for mz_cfg in /opt/marzban/xray_config.json /var/lib/marzban/xray_config.json; do
        [[ -f "$mz_cfg" ]] && cfg_files+=("$mz_cfg")
    done

    if [[ ${#cfg_files[@]} -gt 0 ]]; then
        while read -r port; do
            add_port "$port"
        done < <(python3 "$py_parser" "${cfg_files[@]}" 2>/dev/null | sort -un || true)
    fi

    # ── 4. X-UI / 3x-ui SQLite 数据库读取 ───────────────────
    # [BUG16 FIX] X-UI 节点端口存储在 SQLite 中，JSON 解析完全覆盖不到
    local _xui_found=0
    for db in /etc/x-ui/x-ui.db \
              /usr/local/x-ui/bin/x-ui.db \
              /opt/3x-ui/bin/x-ui.db \
              /usr/local/x-ui/x-ui.db; do
        [[ -f "$db" ]] || continue
        _xui_found=1
        if command -v sqlite3 &>/dev/null; then
            while read -r xui_port; do
                [[ "$xui_port" =~ ^[0-9]+$ ]] && add_port "$xui_port"
            done < <(sqlite3 "$db" \
                "SELECT port FROM inbounds WHERE enable=1;" 2>/dev/null || true)
            ok "已从 X-UI 数据库读取启用节点端口: $db"
        else
            warn "检测到 X-UI 数据库 $db，但 sqlite3 未安装"
            warn "安装后可自动读取: apt install sqlite3 / yum install sqlite"
            warn "★ 请确保所有 X-UI/3x-ui 节点处于【运行中】状态后再执行本脚本！"
        fi
    done
    [[ $_xui_found -eq 0 ]] || true  # suppress shellcheck

    # ── 5. Marzban 面板提示 ───────────────────────────────────
    if [[ -f /opt/marzban/.env || -f /etc/opt/marzban/.env ]]; then
        local mz_env="/opt/marzban/.env"
        [[ -f "$mz_env" ]] || mz_env="/etc/opt/marzban/.env"
        local mz_port
        mz_port=$(grep -E '^UVICORN_PORT\s*=' "$mz_env" 2>/dev/null \
            | cut -d= -f2 | tr -d ' \r')
        [[ -n "$mz_port" ]] && info "Marzban 面板后端端口: $mz_port（通常不对外暴露）"
        warn "★ Marzban 节点端口存储在数据库，请确保所有节点处于【运行中】状态！"
    fi

    # ── 6. 233boy xray 文件名端口兜底 ────────────────────────
    local conf_dirs=(
        /etc/xray/conf /etc/xray/confs
        /usr/local/etc/xray/conf /usr/local/etc/xray/confs
    )
    for d in "${conf_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local fname_port
            # 233boy 命名约定: 端口号作为文件名前缀（如 443.json）
            fname_port=$(basename "$f" .json | grep -oE '^[0-9]+$' || true)
            [[ -z "$fname_port" ]] && \
                fname_port=$(basename "$f" | grep -oE '^[0-9]+' || true)
            [[ -n "$fname_port" ]] && add_port "$fname_port"
        done
    done
}

# ============================================================
# apply_hop: 应用单条端口跳跃规则（IPv4 + IPv6）
# ============================================================
apply_hop() {
    local s=$1 e=$2 t=$3

    # 清除相同范围的旧 DNAT 规则（避免重复叠加）
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep "dpts:${s}:${e}" | awk '{print $1}' | sort -rn)
    for n in $nums; do iptables -t nat -D PREROUTING "$n" 2>/dev/null || true; done

    # Hysteria2 是纯 UDP；加 TCP 规则是为了兼容 TCP 版跳跃场景（如 TUIC-TCP-fallback）
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}" 2>/dev/null || \
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
        -j DNAT --to-destination "0.0.0.0:${t}"

    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}" 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
        -j DNAT --to-destination "0.0.0.0:${t}"

    # INPUT 链必须放行跳跃范围（DNAT 到本机后包走 INPUT 而非 FORWARD）
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT

    # IPv6 端口跳跃（全部加 || true，部分旧内核不支持 ip6tables NAT）
    if command -v ip6tables &>/dev/null; then
        ip6tables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
            -j DNAT --to-destination ":${t}" 2>/dev/null || true
        ip6tables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
            -j DNAT --to-destination ":${t}" 2>/dev/null || true
        ip6tables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
            || ip6tables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null || true
        ip6tables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
            || ip6tables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null || true
    fi
}

# ============================================================
# flush_rules: 清空 iptables 规则（含 Docker 保护）
# [BUG10 FIX] 清空前检测 Docker，清空后重启 Docker 重建网络
# ============================================================
flush_rules() {
    info "清理旧规则..."

    # 检测 Docker 是否运行
    _DOCKER_RUNNING=0
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        _DOCKER_RUNNING=1
        warn "检测到 Docker 正在运行，清空 iptables 后将自动重启 Docker 以重建网络规则..."
    fi

    # IPv4 清空
    iptables -P INPUT   ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables -F         2>/dev/null || true
    iptables -X         2>/dev/null || true
    iptables -t nat    -F 2>/dev/null || true
    iptables -t nat    -X 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true

    # IPv6 清空
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   ACCEPT 2>/dev/null || true
        ip6tables -P FORWARD ACCEPT 2>/dev/null || true
        ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
        ip6tables -F         2>/dev/null || true
        ip6tables -X         2>/dev/null || true
        ip6tables -t nat    -F 2>/dev/null || true
        ip6tables -t nat    -X 2>/dev/null || true
        ip6tables -t mangle -F 2>/dev/null || true
    fi
}

# ============================================================
# apply_rules: 应用完整防火墙规则集（IPv4 + IPv6）
# [BUG9 FIX]  FORWARD --ctstate DNAT → NEW + ESTABLISHED,RELATED
# [BUG11 FIX] 新增完整 ip6tables 规则（含 ICMPv6 NDP 必须放行）
# [BUG13 FIX] SSH hitcount 6 → 10
# ============================================================
apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        info "[预览] 开放端口: ${OPEN_PORTS[*]:-无}"
        [[ ${#HOP_RULES[@]} -gt 0 ]] && for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "[预览] 端口跳跃: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        return 0
    fi

    flush_rules

    # ═══════════════════════════════════════════════════════
    #  IPv4 规则
    # ═══════════════════════════════════════════════════════
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    # 回环接口全放行
    iptables -A INPUT -i lo -j ACCEPT

    # 已建立连接双向放行
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP ping 限速放行（防 ICMP 洪泛）
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # ── SSH 防暴力破解 ──────────────────────────────────────
    # [BUG13 FIX] hitcount 6 → 10：避免 Termius/MobaXterm 多路复用触发封锁
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH_BF --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m recent --name SSH_BF --update --seconds 60 --hitcount 10 -j DROP
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # ── 开放代理端口 ────────────────────────────────────────
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        for port in "${OPEN_PORTS[@]}"; do
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done
    fi

    # ── FORWARD 链（NAT 转发必需）───────────────────────────
    # [BUG9 FIX] --ctstate DNAT 是无效状态（应为 --ctstatus DNAT）
    # 正确做法: 放行 ESTABLISHED,RELATED + NEW 连接
    # 说明：DNAT 到本机端口时包走 INPUT 而非 FORWARD，FORWARD 主要用于
    #       "DNAT 到其他主机" 的转发场景
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate NEW -j ACCEPT

    # ── 端口跳跃（Hysteria2 H2 协议必须）──────────────────
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            [[ -n "${HOP_S:-}" && -n "${HOP_E:-}" && -n "${HOP_T:-}" ]] || continue
            apply_hop "$HOP_S" "$HOP_E" "$HOP_T"
            ok "端口跳跃已应用: ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    fi

    # 限速日志丢弃（debug 用，线上可注释掉）
    iptables -A INPUT -m limit --limit 5/min \
        -j LOG --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP

    # ═══════════════════════════════════════════════════════
    #  IPv6 规则（[BUG11 FIX] 新增完整 ip6tables 支持）
    #  甲骨文云 ARM / 现代 VPS 强依赖 IPv6 双栈
    # ═══════════════════════════════════════════════════════
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   DROP  2>/dev/null || true
        ip6tables -P FORWARD DROP  2>/dev/null || true
        ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true

        ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED \
            -j ACCEPT 2>/dev/null || true

        # ── ICMPv6 必须放行 ─────────────────────────────────
        # NDP（邻居发现协议）是 IPv6 网络正常工作的基础，严禁 DROP ALL ICMPv6
        # 缺少这些规则会导致 IPv6 地址解析失败、网络完全不通
        for icmpv6_type in \
            neighbor-solicitation   \
            neighbor-advertisement  \
            router-solicitation     \
            router-advertisement    \
            redirect; do
            ip6tables -A INPUT -p icmpv6 --icmpv6-type "$icmpv6_type" \
                -j ACCEPT 2>/dev/null || true
        done
        # ICMPv6 ping 限速放行
        ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request \
            -m limit --limit 5/sec --limit-burst 10 -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -p icmpv6 -j DROP 2>/dev/null || true

        # ── SSH（IPv6）防暴力破解 ───────────────────────────
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" \
            -m recent --name SSH6_BF --set 2>/dev/null || true
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" \
            -m recent --name SSH6_BF --update --seconds 60 --hitcount 10 \
            -j DROP 2>/dev/null || true
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" \
            -j ACCEPT 2>/dev/null || true

        # ── 开放代理端口（IPv6）────────────────────────────
        if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
            for port in "${OPEN_PORTS[@]}"; do
                ip6tables -A INPUT -p tcp --dport "$port" \
                    -j ACCEPT 2>/dev/null || true
                ip6tables -A INPUT -p udp --dport "$port" \
                    -j ACCEPT 2>/dev/null || true
            done
        fi

        ip6tables -A FORWARD -m conntrack \
            --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        ip6tables -A FORWARD -m conntrack \
            --ctstate NEW -j ACCEPT 2>/dev/null || true

        ip6tables -A INPUT -j DROP 2>/dev/null || true
        ok "IPv6 防火墙规则已应用"
    else
        warn "ip6tables 未找到，跳过 IPv6 规则配置"
    fi

    # ── Docker 重启（清空 iptables 后必须重建 Docker 网络）──
    # [BUG10 FIX] 防止容器断网
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        info "重启 Docker 以重建容器网络规则..."
        systemctl restart docker 2>/dev/null \
            || service docker restart 2>/dev/null \
            || true
        ok "Docker 已重启，容器网络规则已重建"
    fi
}

# ============================================================
# save_rules: 持久化规则（含 ip6tables）
# [BUG14 FIX] iptables-restore 路径动态检测，非硬编码 /sbin/
# ============================================================
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0
    mkdir -p /etc/iptables

    # 保存 IPv4 规则
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    # 保存 IPv6 规则
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi

    if command -v netfilter-persistent &>/dev/null; then
        # Debian/Ubuntu 推荐方式
        netfilter-persistent save &>/dev/null || true
    else
        # 手动创建 systemd 服务
        # [BUG14 FIX] 使用 command -v 动态查找路径，兼容不同发行版
        local ipt_restore ip6t_restore
        ipt_restore=$(command -v iptables-restore 2>/dev/null \
            || echo "/usr/sbin/iptables-restore")
        ip6t_restore=$(command -v ip6tables-restore 2>/dev/null \
            || echo "/usr/sbin/ip6tables-restore")

        cat > /etc/systemd/system/iptables-restore.service << SVC
[Unit]
Description=Restore iptables rules (port.sh v${VERSION})
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target

[Service]
Type=oneshot
ExecStart=${ipt_restore} /etc/iptables/rules.v4
ExecStartPost=-${ip6t_restore} /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC
        systemctl daemon-reload  &>/dev/null || true
        systemctl enable iptables-restore.service &>/dev/null || true
    fi
    ok "规则已保存，重启后自动生效"
}

# ============================================================
# show_status: 显示防火墙当前状态
# ============================================================
show_status() {
    hr; echo -e "${C}防火墙当前状态 (port.sh v${VERSION})${W}"; hr

    echo -e "${G}▸ IPv4 开放端口 (iptables INPUT ACCEPT):${W}"
    iptables -L INPUT -n 2>/dev/null \
        | grep ACCEPT | grep -oE 'dpts?:[0-9:]+' \
        | sort -u | sed 's/dpts\?:/  • /' || true

    echo -e "\n${G}▸ 端口跳跃 (NAT PREROUTING DNAT):${W}"
    local has_nat=0
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local r t
        r=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+')
        # [BUG4 FIX] 兼容两种格式
        t=$(echo "$line" \
            | grep -oE 'to:(:[0-9]+|[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+)' \
            | grep -oE '[0-9]+$')
        [[ -n "$r" && -n "$t" ]] && echo "  • ${r//:/-} → :${t}" && has_nat=1
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
    [[ $has_nat -eq 0 ]] && echo "  （无）"

    echo -e "\n${G}▸ 公网监听端口 (ss -tulnp):${W}"
    while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"')
        printf "  • %-6s %s\n" "$p" "${proc:-(未知进程)}"
    done < <(get_public_ports)

    if command -v ip6tables &>/dev/null; then
        echo -e "\n${G}▸ IPv6 开放端口 (ip6tables INPUT ACCEPT):${W}"
        ip6tables -L INPUT -n 2>/dev/null \
            | grep ACCEPT | grep -oE 'dpts?:[0-9:]+' \
            | sort -u | sed 's/dpts\?:/  • /' || echo "  （无或未配置）"
    fi

    echo -e "\n${G}▸ 关键 sysctl 参数:${W}"
    for param in \
        net.ipv4.ip_forward \
        net.ipv6.conf.all.forwarding \
        net.ipv4.tcp_timestamps \
        net.ipv4.conf.all.rp_filter; do
        printf "  • %-45s = %s\n" "$param" \
            "$(sysctl -n "$param" 2>/dev/null || echo '未知')"
    done

    echo -e "\n${G}▸ 防火墙前端状态:${W}"
    printf "  • %-20s %s\n" "firewalld:" \
        "$(systemctl is-active firewalld 2>/dev/null || echo '未安装/未运行')"
    printf "  • %-20s %s\n" "ufw:" \
        "$(systemctl is-active ufw 2>/dev/null || echo '未安装/未运行')"
    if command -v docker &>/dev/null; then
        printf "  • %-20s %s\n" "docker:" \
            "$(systemctl is-active docker 2>/dev/null || echo '未知')"
    fi
    hr
}

# ============================================================
# reset_fw: 重置防火墙为全部放行
# ============================================================
reset_fw() {
    echo -e "${R}⚠  清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
    iptables -F; iptables -X
    iptables -t nat    -F; iptables -t nat    -X
    iptables -t mangle -F

    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
        ip6tables -F; ip6tables -X
        ip6tables -t nat    -F 2>/dev/null || true
        ip6tables -t nat    -X 2>/dev/null || true
        ip6tables -t mangle -F 2>/dev/null || true
    fi

    save_rules
    ok "防火墙已重置为全部放行（IPv4 + IPv6）"
}

# ============================================================
# add_hop_interactive: 手动交互式添加端口跳跃
# ============================================================
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加 Hysteria2 端口跳跃规则${W}"; hr
    echo -e "${Y}说明: 端口跳跃将多个外部端口的流量 DNAT 到代理实际监听端口${W}"
    echo -e "${Y}示例: 外部 20000-50000 → 内部 :443${W}"
    echo
    read -rp "跳跃端口范围（如 20000-50000）: " hop_range
    read -rp "目标端口（代理实际监听端口，如 443）: " target_port

    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] \
        || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] \
        || err "目标端口格式错误，必须是数字"
    [[ "$target_port" -ge 1 && "$target_port" -le 65535 ]] \
        || err "目标端口超出范围 (1-65535)"

    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -lt "$e" ]] || err "起始端口必须小于结束端口"
    [[ "$s" -ge 1024  ]] || warn "起始端口 < 1024，可能与系统端口冲突"

    apply_hop "$s" "$e" "$target_port"
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 添加完成"
    echo -e "${C}验证命令: iptables -t nat -L PREROUTING -n${W}"
}

# ============================================================
# show_summary: 最终汇总输出
# ============================================================
show_summary() {
    hr; echo -e "${G}🎉 防火墙配置完成！（port.sh v${VERSION}）${W}"; hr

    echo -e "${C}SSH 端口  :${W} $SSH_PORT  ${Y}（防暴力破解: 60秒内限10次连接）${W}"
    echo -e "${C}开放端口  :${W} ${OPEN_PORTS[*]:-（无）}"

    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃  :${W}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            echo -e "  ${G}•${W} UDP+TCP ${HOP_S}-${HOP_E} → :${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置（Hysteria2 需要）"
        echo -e "  ${Y}如需手动添加: bash port.sh --add-hop${W}"
    fi

    hr
    echo -e "${Y}⚠  重要提示：${W}"
    echo -e "  ${R}▸ 甲骨文云 / AWS / 阿里云 等平台：${W}"
    echo    "    本机防火墙规则生效后，还需前往【云控制台】单独放行！"
    echo    "    甲骨文: VCN → 安全列表/NSG 入站规则"
    echo    "    AWS:    安全组 Inbound 规则"
    echo    "    阿里云: 安全组规则"
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        echo -e "  ${Y}▸ Docker 已重启以重建网络规则，如异常: docker ps${W}"
    fi
    if command -v ip6tables &>/dev/null; then
        echo -e "  ${G}▸ IPv6 防火墙规则已同步配置${W}"
    fi

    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态   : bash port.sh --status"
    echo "  手动加跳跃 : bash port.sh --add-hop"
    echo "  重置防火墙 : bash port.sh --reset"
    echo "  预览不改动 : bash port.sh --dry-run"
    echo "  查看IPv4   : iptables -L -n -v"
    echo "  查看NAT    : iptables -t nat -L -n -v"
    echo "  查看IPv6   : ip6tables -L -n -v"
    hr
}

# ============================================================
# main
# ============================================================
main() {
    trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM

    echo -e "${B}══════════════════════════════════════════${W}"
    echo -e "${G}    代理节点防火墙管理脚本 v${VERSION}${W}"
    echo -e "${B}══════════════════════════════════════════${W}"

    # ── 单功能模式 ──────────────────────────────────────────
    [[ $_status -eq 1 ]] && { detect_ssh; show_status;       exit 0; }
    [[ $_reset  -eq 1 ]] && { detect_ssh; reset_fw;          exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;           exit 0; }

    # ── 主流程 ─────────────────────────────────────────────
    install_deps
    detect_ssh

    # ① 先检测已有跳跃规则（add_port 会排除跳跃范围内的端口）
    detect_existing_hop_rules
    detect_hysteria_hop

    # ② 综合扫描端口（ss 实时 + 配置文件 + 数据库）
    detect_ports

    # 确保 80/443 始终开放（HTTP/HTTPS 基础需求）
    add_port 80
    add_port 443

    # 对开放端口列表排序去重
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un) || true
    fi

    # ── 预览摘要 ─────────────────────────────────────────────
    echo
    info "即将开放端口 : ${OPEN_PORTS[*]:-（无）}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "端口跳跃配置 : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置，如需手动添加: bash port.sh --add-hop"
    fi
    echo

    # ── 应用规则 ─────────────────────────────────────────────
    apply_rules
    save_rules
    show_summary
}

main "$@"
