# port.sh v4.5 更新日志

## 发布日期
2026-04-23

## 修复的严重问题

### 🔴 [v4.5-1] H2端口跳跃范围验证增强（Critical）
**问题**: v4.4 在交互式添加端口跳跃时，缺少关键验证：
- 未检查目标端口是否在跳跃范围内（会导致DNAT死循环）
- 未检查端口范围大小（可能创建6万+规则导致系统崩溃）
- 未验证结束端口上限

**修复**:
```bash
# 完整的端口范围验证
[[ "$s" -ge 1 && "$s" -le 65535 ]] || err "起始端口超出范围 (1-65535)"
[[ "$e" -ge 1 && "$e" -le 65535 ]] || err "结束端口超出范围 (1-65535)"

# 检查范围大小（防止性能问题）
local range_size=$((e - s + 1))
[[ "$range_size" -le 50000 ]] || err "端口范围过大 ($range_size 个端口)，建议不超过 50000"

# 检查目标端口是否在跳跃范围内（会导致死循环）
[[ "$target_port" -lt "$s" || "$target_port" -gt "$e" ]] \
    || err "目标端口 $target_port 不能在跳跃范围 $s-$e 内（会导致死循环）"
```

**影响**: 防止用户配置错误导致防火墙失效或系统性能问题

---

### 🔴 [v4.5-2] Python临时文件竞态条件修复（Critical）
**问题**: v4.4 的 fallback 路径使用 `$$`（当前shell PID），在并发执行时可能冲突；且没有检查 `/tmp` 是否可写。

**修复**:
```bash
_PY_PARSER=$(mktemp /tmp/_fw_parse_ports_XXXXXX.py 2>/dev/null)
if [[ -z "$_PY_PARSER" || ! -w "$(dirname "$_PY_PARSER" 2>/dev/null || echo /tmp)" ]]; then
    # 尝试用户目录
    local cache_dir="${HOME}/.cache"
    mkdir -p "$cache_dir" 2>/dev/null || cache_dir="/tmp"
    _PY_PARSER="${cache_dir}/_fw_parse_ports_$$.py"
    if ! touch "$_PY_PARSER" 2>/dev/null; then
        warn "无法创建临时文件，跳过配置文件解析"
        _PY_PARSER=""
    fi
fi
```

**影响**: 提高脚本在受限环境下的稳定性

---

### 🔴 [v4.5-3] IPv6 DNAT 目标地址优化（Critical）
**问题**: v4.4 硬编码 `[::]`（任意地址），在某些内核版本中 DNAT 到 `[::]` 可能不工作。

**修复**:
```bash
# 优先使用本机全局IPv6地址，回退到本地回环[::1]
local ipv6_target="[::1]"
local ipv6_addr
ipv6_addr=$(ip -6 addr show scope global 2>/dev/null \
    | grep -oP '(?<=inet6\s)[\da-f:]+' | head -1)
[[ -n "$ipv6_addr" ]] && ipv6_target="[${ipv6_addr}]"

ip6tables -t nat -A PREROUTING -p udp --dport "${s}:${e}" \
    -j DNAT --to-destination "${ipv6_target}:${t}" 2>/dev/null || true
```

**影响**: 提高IPv6端口跳跃的兼容性和可靠性

---

## 改进的中等问题

### 🟡 [v4.5-4] Python解析器初始化失败处理
**改进**: 当临时文件创建失败时，不再静默失败，而是：
1. 设置 `_PY_PARSER=""` 标记失败
2. 输出警告信息
3. 跳过配置文件解析，仅依赖 ss 实时扫描

**代码**:
```bash
if [[ -z "$_PY_PARSER" ]]; then
    warn "Python解析器初始化失败，仅依赖 ss 实时扫描结果"
else
    cat > "$_PY_PARSER" << 'PYEOF'
    # ... Python代码 ...
fi
```

---

## 版本对比

| 特性 | v4.4 | v4.5 |
|------|------|------|
| 端口跳跃范围验证 | ⚠️ 不完整 | ✅ 完整 |
| 死循环检测 | ❌ 无 | ✅ 有 |
| 临时文件fallback | ⚠️ 简单 | ✅ 增强 |
| IPv6 DNAT地址 | ⚠️ 硬编码 | ✅ 动态 |
| 错误处理 | ⚠️ 部分 | ✅ 完善 |

---

## 升级建议

### 从 v4.4 升级到 v4.5
```bash
# 备份当前版本
cp port.sh port.sh.v4.4.backup

# 下载新版本
curl -fsSL https://raw.githubusercontent.com/vpn3288/iptables/main/port.sh -o port.sh

# 验证语法
bash -n port.sh

# 运行（会自动保留现有规则）
bash port.sh
```

### 兼容性
- ✅ 完全向后兼容 v4.4
- ✅ 保留所有已有功能
- ✅ 不影响现有配置

---

## 测试建议

### 1. 端口跳跃验证测试
```bash
# 测试死循环检测（应该报错）
bash port.sh --add-hop
# 输入: 20000-50000
# 输入: 30000  ← 在范围内，应该报错

# 测试正常配置（应该成功）
bash port.sh --add-hop
# 输入: 20000-50000
# 输入: 443  ← 不在范围内，应该成功
```

### 2. IPv6 DNAT 测试
```bash
# 查看IPv6 NAT规则
ip6tables -t nat -L PREROUTING -n -v

# 应该看到类似：
# DNAT  udp  --  *  *  ::/0  ::/0  udp dpts:20000:50000 to:[2001:db8::1]:443
# 或
# DNAT  udp  --  *  *  ::/0  ::/0  udp dpts:20000:50000 to:[::1]:443
```

### 3. 临时文件测试
```bash
# 模拟 /tmp 不可写
sudo chmod 000 /tmp
bash port.sh --dry-run
# 应该看到警告但不崩溃

# 恢复权限
sudo chmod 1777 /tmp
```

---

## 已知限制

1. **端口范围上限**: 限制为50000个端口，超过会报错
   - 原因: 过大的范围会导致iptables性能问题
   - 解决: 如需更大范围，修改脚本中的 `50000` 常量

2. **IPv6地址选择**: 自动选择第一个全局IPv6地址
   - 原因: 多IPv6地址时可能不是期望的地址
   - 解决: 手动编辑 `apply_hop()` 函数指定地址

---

## 贡献者
- 原作者: vpn3288
- v4.5 修复: AI代码审查 + 老G

## 许可证
与原项目保持一致
