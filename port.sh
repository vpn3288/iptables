#!/bin/bash
# ============================================================
# iptables 防火墙管理脚本 v6.0
# 架构：Xray VLESS Reality 直连转发（无 WireGuard）
# 支持角色：
#   relay   — 中转机（Xray 多入站转发，用户连接的服务器）
#   landing — 落地机（Xray 出口，流量最终出口）
#   node    — 普通代理节点（独立节点，不参与中转）
# 支持系统：Ubuntu 22/24, Debian 11/12, CentOS/RHEL 8+
# ============================================================
set -uo pipefail

# ── 颜色 ────────────────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

# ── 版本 ────────────────────────────────────────────────────
VERSION="6.0"

# ── 全局变量 ────────────────────────────────────────────────
SSH_PORT=""
ROLE="auto"        # auto | relay | landing | node
DRY_RUN=false

OPEN_PORTS=()      # 最终需要 INPUT 放行的端口列表
HOP_RULES=()       # 端口跳跃规则，格式: "起始-结束->目标"

# 黑名单端口（危险服务端口，绝不开放）
# 注意：10085 是 Xray API 本地监听端口，但它绑定 127.0.0.1，
#       防火墙层面不需要处理，不放入黑名单
BLACKLIST_PORTS=(
    23 25 53 69 111
    135 137 138 139 445
    110 143 465 587 993 995
    514 631 323 2049
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902
    8181 9090 3000 3001
    8000 8001 54321 62789
)

# 排除这些进程的端口（系统服务，不是代理端口）
EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|named|unbound|ntpd|avahi"

# ── 参数解析 ────────────────────────────────────────────────
_status=0 _reset=0 _addhop=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)  DRY_RUN=true ;;
        --status)   _status=1 ;;
        --reset)    _reset=1 ;;
        --add-hop)  _addhop=1 ;;
        --relay)    ROLE="relay" ;;
        --landing)  ROLE="landing" ;;
        --node)     ROLE="node" ;;
        --help|-h)
            echo "用法: bash port.sh [选项]"
            echo ""
            echo "  (无参数)    交互式完整配置（自动检测角色）"
            echo "  --relay     强制指定为中转机模式"
            echo "  --landing   强制指定为落地机模式"
            echo "  --node      强制指定为普通代理节点模式"
            echo "  --status    查看当前规则和端口"
            echo "  --reset     清空所有规则（全部放行）"
            echo "  --add-hop   手动添加端口跳跃规则"
            echo "  --dry-run   预览模式，不实际修改"
            exit 0 ;;
        *) err "未知参数: $1，使用 --help 查看帮助" ;;
    esac
    shift
done

# ============================================================
# 工具函数
# ============================================================

# 获取公网监听端口（排除本地回环和系统进程）
get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | while read -r p; do
            # 只收集非临时端口（< 32768）
            [[ "$p" -lt 32768 ]] && echo "$p" || true
          done \
        | sort -un || true
}

# 获取默认出口网卡
get_default_iface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' \
        || ip link show 2>/dev/null | awk -F': ' '/^[0-9]+: [^lo]/{print $2; exit}' \
        || echo "eth0"
}

# 解析端口跳跃规则
parse_hop() {
    local rule=$1
    HOP_S=$(echo "$rule" | cut -d'-' -f1)
    HOP_E=$(echo "$rule" | cut -d'-' -f2 | cut -d'>' -f1 | tr -d '>')
    HOP_T=$(echo "$rule" | grep -oE '[0-9]+$')
}

# 判断端口是否在跳跃范围内
port_in_hop_range() {
    local p=$1
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

# 判断端口是否在黑名单
is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 1  # SSH 端口不在黑名单（单独处理）
    for b in "${BLACKLIST_PORTS[@]}"; do
        [[ "$p" == "$b" ]] && return 0
    done
    return 1
}

# 安全添加端口到开放列表
add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]             || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                 && { warn "端口 $p 在黑名单中，跳过"; return 0; }
    port_in_hop_range "$p"             && return 0  # 跳跃范围内由 NAT 处理
    [[ " ${OPEN_PORTS[*]:-} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

# ============================================================
# 初始化：禁用冲突防火墙 + 安装 iptables + sysctl
# ============================================================
install_deps() {
    info "初始化环境..."

    # ── 完全禁用 nftables（防止与 iptables 冲突）────────────
    info "禁用 nftables..."
    systemctl stop    nftables &>/dev/null || true
    systemctl disable nftables &>/dev/null || true
    systemctl mask    nftables &>/dev/null || true
    if command -v nft &>/dev/null; then
        nft flush ruleset 2>/dev/null || true
    fi
    [[ -f /etc/nftables.conf ]] && > /etc/nftables.conf || true
    ok "nftables 已完全禁用"

    # ── 禁用其他防火墙管理工具 ──────────────────────────────
    for svc in ufw firewalld; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            systemctl stop    "$svc" &>/dev/null || true
            systemctl disable "$svc" &>/dev/null || true
            systemctl mask    "$svc" &>/dev/null || true
            ok "已禁用 $svc"
        fi
    done

    # ── 安装 iptables ────────────────────────────────────────
    local pkgs=()
    command -v iptables      &>/dev/null || pkgs+=(iptables)
    command -v iptables-save &>/dev/null || pkgs+=(iptables)
    command -v ss            &>/dev/null || pkgs+=(iproute2)
    command -v python3       &>/dev/null || pkgs+=(python3)
    command -v jq            &>/dev/null || pkgs+=(jq)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null || true
            apt-get install -y -qq "${pkgs[@]}" iptables-persistent 2>/dev/null || \
            apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y iptables iptables-services iproute python3 jq 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y iptables iptables-services iproute python3 jq 2>/dev/null || true
        fi
        command -v iptables &>/dev/null || err "iptables 安装失败，请手动安装"
    fi

    # ── 切换为 legacy 模式（避免 nft 后端干扰）──────────────
    if command -v update-alternatives &>/dev/null; then
        update-alternatives --set iptables  /usr/sbin/iptables-legacy  &>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy &>/dev/null || true
        ok "iptables 已切换为 legacy 模式"
    fi

    # ── sysctl：开启转发，关闭危险选项 ──────────────────────
    cat > /etc/sysctl.d/98-fw.conf << 'EOF'
# port.sh v6.0
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_timestamps = 0
# rp_filter=2 宽松模式，兼容 DNAT 端口跳跃的 UDP 回包
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
    sysctl -p /etc/sysctl.d/98-fw.conf &>/dev/null || true
    ok "sysctl 配置完成"
}

# ── 检测 SSH 端口 ────────────────────────────────────────────
detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null \
        | grep sshd \
        | grep -oE ':[0-9]+' \
        | grep -oE '[0-9]+' \
        | head -1 || true)
    [[ -z "$SSH_PORT" ]] && \
        SSH_PORT=$(awk '/^Port /{print $2;exit}' /etc/ssh/sshd_config 2>/dev/null || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ============================================================
# 角色自动检测（Xray 架构专用）
# ============================================================
detect_role() {
    if [[ "$ROLE" != "auto" ]]; then
        ok "角色已手动指定: $ROLE"
        return
    fi

    local xray_nodes="/usr/local/etc/xray/nodes.json"
    local xray_cfg="/usr/local/etc/xray/config.json"
    local zhongzhuan_info="/root/xray_zhongzhuan_info.txt"
    local luodi_info="/root/xray_luodi_info.txt"

    # 优先级1：中转机标志文件
    if [[ -f "$xray_nodes" ]] || [[ -f "$zhongzhuan_info" ]]; then
        # nodes.json 有记录 = 确定是中转机
        local node_count=0
        [[ -f "$xray_nodes" ]] && \
            node_count=$(python3 -c "import json; d=json.load(open('$xray_nodes')); print(len(d.get('nodes',[])))" 2>/dev/null \
                || jq '.nodes | length' "$xray_nodes" 2>/dev/null \
                || echo 0)
        if [[ "$node_count" -gt 0 ]] || [[ -f "$zhongzhuan_info" ]]; then
            ROLE="relay"
            ok "自动检测角色: 中转机 (relay) — 已对接 ${node_count} 台落地机"
            return
        fi
    fi

    # 优先级2：落地机标志文件
    if [[ -f "$luodi_info" ]]; then
        ROLE="landing"
        ok "自动检测角色: 落地机 (landing) — 检测到 xray_luodi_info.txt"
        return
    fi

    # 优先级3：v2ray-agent（常用落地机工具）
    if [[ -d /etc/v2ray-agent/xray/conf || -d /etc/v2ray-agent/sing-box/conf ]]; then
        ROLE="landing"
        ok "自动检测角色: 落地机 (landing) — 检测到 v2ray-agent"
        return
    fi

    # 优先级4：有 xray 配置但无中转标志 = 普通节点或落地机
    if [[ -f "$xray_cfg" ]]; then
        # 检查配置中是否有多个入站（中转机特征）
        local inbound_count=0
        inbound_count=$(python3 -c "
import json
d=json.load(open('$xray_cfg'))
# 排除 api-in 内置管理入站
ibs=[i for i in d.get('inbounds',[]) if i.get('tag','') not in ('api-in','api')]
print(len(ibs))
" 2>/dev/null || echo 0)

        if [[ "$inbound_count" -gt 2 ]]; then
            ROLE="relay"
            ok "自动检测角色: 中转机 (relay) — 配置含 ${inbound_count} 个入站"
        else
            ROLE="node"
            ok "自动检测角色: 普通代理节点 (node)"
        fi
        return
    fi

    # 默认：普通节点
    ROLE="node"
    ok "自动检测角色: 普通代理节点 (node)（默认）"
}

# ============================================================
# 端口检测：从 Xray 配置文件解析
# ============================================================

# 用 Python 从 JSON 配置文件提取入站端口
_parse_xray_ports_py() {
    local files=("$@")
    [[ ${#files[@]} -eq 0 ]] && return

    python3 - "${files[@]}" << 'PYEOF' 2>/dev/null || true
import json, sys

LOCAL_ADDRS = ('127.', '::1', 'localhost')

def is_local(addr):
    return any(str(addr or '').startswith(x) for x in LOCAL_ADDRS)

def extract(data):
    ports = []
    # inbounds 数组（Xray/V2Ray 标准格式）
    for ib in (data.get('inbounds') or []):
        if not isinstance(ib, dict): continue
        listen = ib.get('listen', '')
        if is_local(listen): continue
        # 跳过 API 管理入站
        if ib.get('tag', '') in ('api', 'api-in'): continue
        for key in ('port', 'listen_port'):
            p = ib.get(key)
            if isinstance(p, int) and 1 <= p <= 65535:
                ports.append(p)
    # sing-box / hysteria2 顶层 listen 字段
    for src in [data.get('inbound')] + list(data.get('inboundDetour') or []):
        if not isinstance(src, dict): continue
        if is_local(src.get('listen', '')): continue
        p = src.get('port')
        if isinstance(p, int) and 1 <= p <= 65535:
            ports.append(p)
    return sorted(set(ports))

for fpath in sys.argv[1:]:
    try:
        with open(fpath) as fp:
            for p in extract(json.load(fp)):
                print(p)
    except Exception:
        pass
PYEOF
}

# 从 nodes.json 提取中转机入站端口
detect_relay_ports() {
    local nodes_file="/usr/local/etc/xray/nodes.json"
    local xray_cfg="/usr/local/etc/xray/config.json"

    info "检测中转机入站端口..."

    # 方法1：从 nodes.json 读取记录的端口
    if [[ -f "$nodes_file" ]]; then
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] && add_port "$port"
        done < <(python3 -c "
import json
with open('$nodes_file') as f:
    d = json.load(f)
for n in d.get('nodes', []):
    p = n.get('inbound_port')
    if p: print(p)
" 2>/dev/null || jq -r '.nodes[].inbound_port' "$nodes_file" 2>/dev/null || true)
    fi

    # 方法2：从 config.json 读取入站端口（补充）
    if [[ -f "$xray_cfg" ]]; then
        while read -r port; do
            add_port "$port"
        done < <(_parse_xray_ports_py "$xray_cfg")
    fi

    # 方法3：从 ss 扫描当前监听（兜底）
    while read -r port; do add_port "$port"; done < <(get_public_ports)

    if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
        warn "未自动检测到中转机入站端口"
        warn "请确认 zhongzhuan.sh 已运行，或手动输入端口"
        _ask_extra_ports
    fi
}

# 落地机 / 普通节点 端口检测
detect_node_ports() {
    info "扫描代理服务监听端口..."

    # 1. ss 实时扫描
    while read -r port; do add_port "$port"; done < <(get_public_ports)

    # 2. 解析所有已知 Xray/V2Ray/sing-box 配置目录
    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray
        /etc/xray
        /usr/local/etc/v2ray
        /etc/v2ray
        /etc/sing-box
        /opt/sing-box
        /usr/local/etc/sing-box
        /etc/v2ray-agent/xray/conf
        /etc/v2ray-agent/sing-box/conf
        /etc/hysteria
        /etc/hysteria2
        /etc/tuic
        /etc/trojan
        /etc/x-ui
        /opt/3x-ui/bin
        /usr/local/x-ui/bin
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/config.json "$d"/*.json \
                  "$d"/conf/*.json "$d"/confs/*.json; do
            [[ -f "$f" ]] && cfg_files+=("$f")
        done
    done

    if [[ ${#cfg_files[@]} -gt 0 ]]; then
        while read -r port; do
            add_port "$port"
        done < <(_parse_xray_ports_py "${cfg_files[@]}" | sort -un)
    fi

    # 3. 文件名端口约定（如 /conf/12345.json）
    for d in /etc/xray/conf /etc/xray/confs \
              /usr/local/etc/xray/conf /usr/local/etc/xray/confs \
              /etc/v2ray-agent/xray/conf; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local p
            p=$(basename "$f" .json | grep -oE '^[0-9]+$' || true)
            [[ -n "$p" ]] && add_port "$p"
        done
    done

    # 4. 默认开放 80/443（大多数代理服务需要）
    add_port 80
    add_port 443
}

# 询问是否手动补充端口
_ask_extra_ports() {
    echo ""
    read -rp "$(echo -e "${Y}是否手动输入额外端口？（多个用空格分隔，回车跳过）: ${W}")" extra
    for p in $extra; do
        [[ "$p" =~ ^[0-9]+$ ]] && add_port "$p"
    done
}

# ============================================================
# 端口跳跃检测
# ============================================================

# 从已有 iptables NAT 规则提取跳跃
detect_existing_hop_rules() {
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local range target
        range=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' \
                | grep -oE '[0-9]+:[0-9]+' | tr ':' '-')
        target=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        [[ -n "$range" && -n "$target" ]] || continue
        local rule="${range}->${target}"
        [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
}

# 从 Hysteria2 配置文件检测端口跳跃
detect_hysteria_hop() {
    local dirs=(/etc/hysteria /etc/hysteria2 /usr/local/etc/hysteria)
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for ext in json yaml yml; do
            local f="${d}/config.${ext}"
            [[ -f "$f" ]] || continue
            local listen_port="" hop_range=""
            if [[ "$ext" == "json" ]]; then
                listen_port=$(grep -oE '"listen"[^:]*:[^"]*":[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -oE '"(portHopping|portRange)"[^:]*:"[0-9]+-[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] || {
                    HOP_RULES+=("$rule")
                    ok "检测到 Hysteria2 端口跳跃: $hop_range → $listen_port"
                }
            fi
        done
    done
}

# ============================================================
# 清理旧规则
# ============================================================
flush_rules() {
    info "清理旧 iptables 规则..."
    iptables  -P INPUT   ACCEPT 2>/dev/null || true
    iptables  -P FORWARD ACCEPT 2>/dev/null || true
    iptables  -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables  -F         2>/dev/null || true
    iptables  -X         2>/dev/null || true
    iptables  -t nat    -F 2>/dev/null || true
    iptables  -t nat    -X 2>/dev/null || true
    iptables  -t mangle -F 2>/dev/null || true
    iptables  -t raw    -F 2>/dev/null || true
    ip6tables -P INPUT   ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
    ip6tables -F         2>/dev/null || true
    ip6tables -t nat    -F 2>/dev/null || true
    ok "旧规则已清空"
}

# ============================================================
# 应用端口跳跃 NAT
# ============================================================
apply_hop_rule() {
    local s=$1 e=$2 t=$3

    # 删除同范围旧规则（避免重复）
    local nums
    nums=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
        | grep "dpts:${s}:${e}" | awk '{print $1}' | sort -rn || true)
    for n in $nums; do
        iptables -t nat -D PREROUTING "$n" 2>/dev/null || true
    done

    # UDP + TCP 都做 DNAT（Hysteria2 是 UDP，VLESS 是 TCP）
    iptables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}"
    iptables -t nat -A PREROUTING -p tcp --dport "${s}:${e}" \
        -j DNAT --to-destination ":${t}"

    # 放行跳跃范围入站（INPUT 层面）
    iptables -C INPUT -p udp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "${s}:${e}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${s}:${e}" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p tcp --dport "${s}:${e}" -j ACCEPT
}

# ============================================================
# 核心：应用防火墙规则
# ============================================================
apply_rules() {
    local wan_iface
    wan_iface=$(get_default_iface)
    info "出口网卡: $wan_iface"

    if [[ "$DRY_RUN" == true ]]; then
        hr
        info "[预览模式] 以下配置不会实际应用"
        info "角色     : $ROLE"
        info "SSH 端口 : $SSH_PORT"
        info "开放端口 : ${OPEN_PORTS[*]:-无}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"
            info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        hr
        return 0
    fi

    flush_rules

    # ════════════════════════════════════════════════════════
    # 通用基础规则（所有角色共用）
    # ════════════════════════════════════════════════════════
    info "应用基础规则..."

    # 默认策略：INPUT/FORWARD DROP，OUTPUT 全放行
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  ACCEPT

    # 本地回环：全放行
    iptables -A INPUT -i lo -j ACCEPT

    # 已建立/关联连接：放行（保证回包正常）
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMP：限速放行（防 ping 洪水）
    iptables -A INPUT -p icmp --icmp-type echo-request \
        -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    # SSH 防暴力破解（60秒内超过6次新连接则丢弃）
    iptables -N SSH_PROTECT 2>/dev/null || iptables -F SSH_PROTECT
    iptables -A SSH_PROTECT -m recent --name SSH_BF --set
    iptables -A SSH_PROTECT -m recent --name SSH_BF \
        --update --seconds 60 --hitcount 6 -j DROP
    iptables -A SSH_PROTECT -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" \
        -m conntrack --ctstate NEW -j SSH_PROTECT

    ok "基础规则已应用 (SSH: $SSH_PORT 防暴力)"

    # ════════════════════════════════════════════════════════
    # 角色专用规则
    # ════════════════════════════════════════════════════════
    case "$ROLE" in

        relay)
            _apply_relay_rules "$wan_iface"
            ;;

        landing|node)
            _apply_node_rules "$wan_iface"
            ;;
    esac

    # ── 兜底：记录并丢弃未匹配流量 ──────────────────────────
    iptables -A INPUT -m limit --limit 3/min -j LOG \
        --log-prefix "[FW-DROP] " --log-level 4
    iptables -A INPUT -j DROP

    ok "所有规则应用完成"
}

# ── 中转机专用规则 ─────────────────────────────────────────
# 架构说明：
#   用户 → 中转机(Xray入站) → 落地机(Xray出站)
#   Xray 在应用层完成转发，iptables 只需：
#   1. 放行用户连接中转机的入站端口（TCP）
#   2. 放行 OUTPUT（Xray 连落地机，默认已 ACCEPT）
#   不需要 FORWARD 规则（不是内核转发，是应用层转发）
#   不需要 MASQUERADE（中转机用自身IP连落地机）
_apply_relay_rules() {
    local wan_iface=$1
    info "应用中转机规则..."

    if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
        warn "未检测到入站端口，中转机可能无法正常服务"
    fi

    # 放行所有检测到的 Xray 入站端口（用户连接用，TCP）
    for port in "${OPEN_PORTS[@]:-}"; do
        [[ -z "$port" ]] && continue
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        ok "放行入站端口: TCP $port"
    done

    # FORWARD：放行已建立连接的回包（Xray 出站连接的回包走这里）
    # 注意：Xray 应用层转发不走 FORWARD，但 OUTPUT→INPUT 回包走 ESTABLISHED
    # 此处 FORWARD 规则是保险措施
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ok "中转机规则应用完成（共 ${#OPEN_PORTS[@]} 个入站端口）"
}

# ── 落地机 / 普通节点 规则 ────────────────────────────────
# 架构说明：
#   中转机/客户端 → 落地机(Xray入站) → 互联网
#   iptables 需要：
#   1. 放行代理入站端口（TCP/UDP）
#   2. 端口跳跃 NAT（如有 Hysteria2）
#   3. MASQUERADE：Xray 代理用户流量出互联网时做 NAT
#   4. FORWARD + DNAT 回包：端口跳跃 NAT 后的转发
_apply_node_rules() {
    local wan_iface=$1
    info "应用${ROLE}规则..."

    # 放行代理端口（TCP + UDP，UDP 兼容 QUIC/Hysteria2）
    for port in "${OPEN_PORTS[@]:-}"; do
        [[ -z "$port" ]] && continue
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    done
    ok "代理端口已放行: ${OPEN_PORTS[*]:-无}"

    # FORWARD：允许已建立连接和 DNAT 后的包通过
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT

    # MASQUERADE：Xray 代理用户流量出互联网（落地机作为出口）
    iptables -t nat -A POSTROUTING -o "$wan_iface" -j MASQUERADE
    ok "MASQUERADE 已启用 → $wan_iface"

    # 端口跳跃 NAT（Hysteria2 等需要）
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"
            [[ -z "${HOP_S:-}" || -z "${HOP_E:-}" || -z "${HOP_T:-}" ]] && continue
            apply_hop_rule "$HOP_S" "$HOP_E" "$HOP_T"
            ok "端口跳跃: ${HOP_S}-${HOP_E} → :${HOP_T}"
        done
    else
        info "未配置端口跳跃（如需添加: bash port.sh --add-hop）"
    fi
}

# ============================================================
# 持久化
# ============================================================
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    # 方法1：netfilter-persistent（Debian/Ubuntu 推荐）
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null || true
        ok "规则已通过 netfilter-persistent 持久化"
        return 0
    fi

    # 方法2：iptables-services（CentOS/RHEL）
    if systemctl list-unit-files 2>/dev/null | grep -q "^iptables\.service"; then
        systemctl enable iptables &>/dev/null || true
        service iptables save &>/dev/null || true
        ok "规则已通过 iptables-services 持久化"
        return 0
    fi

    # 方法3：写 systemd service（通用 fallback）
    cat > /etc/systemd/system/iptables-restore.service << 'SVC'
[Unit]
Description=Restore iptables rules (port.sh v6.0)
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'iptables-restore < /etc/iptables/rules.v4; ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null || true'
ExecReload=/bin/sh -c 'iptables-restore < /etc/iptables/rules.v4'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload  &>/dev/null || true
    systemctl enable iptables-restore.service &>/dev/null || true
    ok "规则已保存至 /etc/iptables/rules.v4，开机自动恢复"
}

# ============================================================
# --status：显示当前状态
# ============================================================
show_status() {
    hr
    echo -e "${C}   防火墙当前状态${W}"
    hr

    echo -e "${G}▸ 角色检测:${W}"
    detect_role 2>/dev/null || true
    echo "  • 当前角色: $ROLE"

    echo -e "\n${G}▸ iptables 后端:${W}"
    if command -v iptables &>/dev/null; then
        local ver
        ver=$(iptables --version 2>/dev/null | head -1)
        echo "  • $ver"
        [[ "$ver" == *"legacy"* ]] \
            && ok "  使用 legacy 后端（正确）" \
            || warn "  可能使用 nft 后端，建议切换"
    fi

    echo -e "\n${G}▸ nftables 状态（应为禁用）:${W}"
    systemctl is-active nftables &>/dev/null \
        && warn "  nftables.service 仍在运行！" \
        || ok   "  nftables.service 已禁用"

    echo -e "\n${G}▸ INPUT 放行端口:${W}"
    iptables -L INPUT -n 2>/dev/null \
        | grep ACCEPT \
        | grep -oE 'dpts?:[0-9:]+' \
        | sort -u \
        | sed 's/dpts\?:/  • /' \
        || echo "  无"

    echo -e "\n${G}▸ 端口跳跃 NAT (PREROUTING):${W}"
    local has_nat=0
    while IFS= read -r line; do
        [[ "$line" == *DNAT* ]] || continue
        local r t
        r=$(echo "$line" | grep -oE 'dpts:[0-9]+:[0-9]+' | grep -oE '[0-9]+:[0-9]+')
        t=$(echo "$line" | grep -oE 'to::[0-9]+' | grep -oE '[0-9]+$')
        [[ -n "$r" && -n "$t" ]] && echo "  • ${r//:/-} → :${t}" && has_nat=1
    done < <(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
    [[ $has_nat -eq 0 ]] && echo "  无"

    echo -e "\n${G}▸ POSTROUTING NAT:${W}"
    iptables -t nat -L POSTROUTING -n 2>/dev/null \
        | grep -v '^target\|^Chain\|^$' \
        | sed 's/^/  • /' \
        || echo "  无"

    echo -e "\n${G}▸ 公网监听端口 (ss):${W}"
    local found=0
    while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
        printf "  • %-6s %s\n" "$p" "${proc:-(未知)}"
        found=1
    done < <(get_public_ports)
    [[ $found -eq 0 ]] && echo "  无公网监听端口"

    echo -e "\n${G}▸ sysctl 关键参数:${W}"
    for param in net.ipv4.ip_forward \
                 net.ipv4.conf.all.rp_filter \
                 net.ipv4.tcp_timestamps; do
        printf "  • %-45s = %s\n" "$param" \
            "$(sysctl -n "$param" 2>/dev/null || echo 未知)"
    done

    echo -e "\n${G}▸ Xray 节点信息:${W}"
    local nodes_file="/usr/local/etc/xray/nodes.json"
    if [[ -f "$nodes_file" ]]; then
        python3 - << PYEOF 2>/dev/null || jq -r '.nodes[]|"  • \(.luodi_ip):\(.luodi_port) → 本机:\(.inbound_port)"' "$nodes_file" 2>/dev/null || echo "  解析失败"
import json
with open("$nodes_file") as f:
    d = json.load(f)
nodes = d.get("nodes", [])
if not nodes:
    print("  无已对接节点")
else:
    for n in nodes:
        print(f"  • 落地机 {n.get('luodi_ip')}:{n.get('luodi_port')} → 本机入站端口 {n.get('inbound_port')}")
PYEOF
    else
        echo "  无 nodes.json（非中转机）"
    fi

    hr
}

# ============================================================
# --reset：清空所有规则
# ============================================================
do_reset() {
    echo -e "${R}⚠ 将清空所有防火墙规则并全部放行，确认？[y/N]: ${W}"
    read -r ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }

    iptables  -P INPUT   ACCEPT
    iptables  -P FORWARD ACCEPT
    iptables  -P OUTPUT  ACCEPT
    iptables  -F; iptables  -X
    iptables  -t nat    -F; iptables -t nat    -X
    iptables  -t mangle -F; iptables -t mangle -X
    iptables  -t raw    -F; iptables -t raw    -X
    ip6tables -P INPUT   ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true

    save_rules
    ok "防火墙已重置，所有流量放行"
}

# ============================================================
# --add-hop：手动添加端口跳跃
# ============================================================
add_hop_interactive() {
    detect_ssh
    hr
    echo -e "${C}手动添加端口跳跃规则${W}"
    hr
    echo "说明：端口跳跃让客户端可以从一个端口范围随机连接，"
    echo "      服务器通过 NAT 将流量统一转到代理实际监听的端口。"
    echo "      常用于 Hysteria2 的 portHopping 功能。"
    echo ""

    read -rp "$(echo -e "${Y}端口范围（如 20000-50000）: ${W}")" hop_range
    read -rp "$(echo -e "${Y}目标端口（代理实际监听端口，如 8443）: ${W}")" target_port

    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] || err "目标端口格式错误"

    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -ge "$e" ]] && err "起始端口须小于结束端口"
    [[ "$s" -lt 1024 ]] && warn "起始端口 < 1024，可能与系统端口冲突"

    apply_hop_rule "$s" "$e" "$target_port"
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 添加成功"
    echo ""
    echo "验证命令："
    echo "  iptables -t nat -L PREROUTING -n -v"
}

# ============================================================
# 确认界面：展示检测结果，等待用户确认
# ============================================================
show_confirm() {
    hr
    echo -e "${G}   配置预览（角色: $ROLE）${W}"
    hr
    echo -e "${C}SSH 端口   :${W} $SSH_PORT  ${Y}（防暴力破解已开启）${W}"

    case "$ROLE" in
        relay)
            echo -e "${C}角色       :${W} 中转机 (relay)"
            echo -e "${C}Xray入站端口:${W}"
            if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
                for p in "${OPEN_PORTS[@]}"; do
                    echo -e "  ${G}•${W} TCP $p（用户连接此端口）"
                done
            else
                echo -e "  ${Y}未检测到，将只放行 SSH${W}"
            fi
            echo ""
            echo -e "${Y}注意：中转机无需 MASQUERADE 和 FORWARD，"
            echo -e "Xray 在应用层完成转发。${W}"
            ;;

        landing|node)
            local role_name="落地机"
            [[ "$ROLE" == "node" ]] && role_name="普通代理节点"
            echo -e "${C}角色       :${W} ${role_name}"
            echo -e "${C}代理端口   :${W} ${OPEN_PORTS[*]:-无（请确认）}"
            if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
                echo -e "${C}端口跳跃   :${W}"
                for rule in "${HOP_RULES[@]:-}"; do
                    [[ -z "$rule" ]] && continue
                    parse_hop "$rule"
                    echo -e "  ${G}•${W} ${HOP_S}-${HOP_E} → ${HOP_T}"
                done
            else
                echo -e "${C}端口跳跃   :${W} 无"
            fi
            echo -e "${C}MASQUERADE :${W} 已启用（代理出口流量 NAT）"
            ;;
    esac
    hr
}

# ============================================================
# 完成摘要
# ============================================================
show_summary() {
    hr
    echo -e "${G}🎉 防火墙配置完成！${W}"
    hr
    echo -e "${C}角色       :${W} $ROLE"
    echo -e "${C}SSH 端口   :${W} $SSH_PORT"
    echo -e "${C}开放端口   :${W} ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃   :${W}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"
            echo -e "  ${G}•${W} ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    fi
    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态   : bash port.sh --status"
    echo "  添加跳跃   : bash port.sh --add-hop"
    echo "  重置防火墙 : bash port.sh --reset"
    echo "  查看规则   : iptables -L -n -v"
    echo "  查看NAT    : iptables -t nat -L -n -v"
    hr
}

# ============================================================
# 主流程
# ============================================================
main() {
    trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM
    hr
    echo -e "${G}   iptables 防火墙管理脚本 v${VERSION}${W}"
    echo -e "${G}   架构: Xray VLESS Reality 直连转发${W}"
    hr

    # 单独子命令
    [[ $_status -eq 1 ]] && { detect_ssh; show_status;        exit 0; }
    [[ $_reset  -eq 1 ]] && { do_reset;                        exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;             exit 0; }

    # ── 完整配置流程 ─────────────────────────────────────────
    install_deps
    detect_ssh
    detect_role

    case "$ROLE" in
        relay)
            # 中转机：检测 Xray 入站端口，不检测端口跳跃
            detect_relay_ports
            detect_existing_hop_rules   # 保留已有的跳跃规则（如果有）
            ;;

        landing|node)
            # 落地机/节点：检测代理端口 + 端口跳跃
            detect_existing_hop_rules
            detect_hysteria_hop
            detect_node_ports
            ;;
    esac

    # 去重排序
    mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]:-}" \
        | grep -v '^$' | sort -un) || true

    # 显示确认界面
    show_confirm

    # 询问是否补充端口
    echo ""
    read -rp "$(echo -e "${Y}是否手动添加额外开放端口？（多个用空格，回车跳过）: ${W}")" extra_ports
    for p in $extra_ports; do
        [[ "$p" =~ ^[0-9]+$ ]] && add_port "$p" && info "手动添加端口: $p"
    done

    echo ""
    read -rp "$(echo -e "${Y}确认应用以上配置？[y/N]: ${W}")" ans
    [[ "${ans,,}" == y ]] || { info "已取消，未做任何修改"; exit 0; }

    apply_rules
    save_rules
    show_summary
}

main "$@"
