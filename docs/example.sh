#!/bin/bash
# xt_NAT IPv6 SNAT/DNAT 示例脚本
#
# 本脚本演示 xt_NAT 模块的完整 IPv6 NAT 配置流程：
#   1. 加载模块并指定地址池
#   2. 配置路由与 NDP，使本机能接收池地址的回包
#   3. 添加 ip6tables 规则（SNAT + DNAT）
#   4. 验证连通性
#
# 使用前请根据实际网络修改下方配置变量。
# 用法: sudo ./example.sh
#       NAT_IF=eth1 POOL_DST=2001:db8:1::/48 sudo ./example.sh

set -e

# ======================== 配置 ========================
# 出口网卡
IF="${NAT_IF:-eth0}"
# IPv6 地址池范围（每个新连接从中随机选取出口地址）
NAT_POOL6="${NAT_POOL6:-2001:db8:1::0-2001:db8:1:ffff:ffff:ffff:ffff:ffff}"
# IPv4 地址池（模块必填参数，若只用 IPv6 可填一个占位范围）
NAT_POOL="${NAT_POOL:-198.51.100.10-198.51.100.20}"
# SNAT 匹配的内网源前缀（不能包含池前缀，否则池地址会 SNAT 自身）
SNAT_SRC="${SNAT_SRC:-2001:db8:0::/48}"
# DNAT 匹配的池前缀（回包目的地址落在此范围）
POOL_DST="${POOL_DST:-2001:db8:1::/48}"
# =====================================================

POOL_START="${NAT_POOL6%%-*}"

echo "=== xt_NAT IPv6 配置示例 ==="
echo "  出口接口:   $IF"
echo "  IPv6 池:    $NAT_POOL6"
echo "  内网前缀:   $SNAT_SRC"
echo "  池前缀:     $POOL_DST"
echo ""

# ---------- Step 1: 清理旧配置 ----------
echo "[1/5] 清理旧规则..."
ip -6 addr del "${POOL_START}/128" dev "$IF" 2>/dev/null || true
ip -6 route del local "${POOL_DST}" dev lo 2>/dev/null || true
ip6tables -t mangle -F PREROUTING  2>/dev/null || true
ip6tables -t mangle -F POSTROUTING 2>/dev/null || true
ip6tables -F INPUT                 2>/dev/null || true

# ---------- Step 2: 加载模块 ----------
echo "[2/5] 加载 xt_NAT 模块..."
modprobe -r xt_NAT 2>/dev/null || true
modprobe xt_NAT \
    nat_pool="$NAT_POOL" \
    nat_pool6="$NAT_POOL6"

echo "  已加载，nat_pool6 = $(cat /sys/module/xt_NAT/parameters/nat_pool6)"

# ---------- Step 3: 配置路由与 NDP ----------
echo "[3/5] 配置路由与 proxy NDP..."

# local route：让内核认为池前缀是"本地"地址
ip -6 route add local "${POOL_DST}" dev lo 2>/dev/null || true

# proxy NDP：本机代答池地址的 NDP 请求
sysctl -qw "net.ipv6.conf.${IF}.proxy_ndp=1" 2>/dev/null || true
ip -6 neigh add proxy "${POOL_START}" dev "$IF" 2>/dev/null || true

# ---------- Step 4: 添加 ip6tables 规则 ----------
echo "[4/5] 添加 ip6tables 规则..."

# DNAT：仅匹配目的为池前缀的回包（在 PREROUTING 改写目的地址）
ip6tables -t mangle -A PREROUTING -d "${POOL_DST}" -j NAT --dnat

# SNAT：仅匹配源为内网前缀的出口包（在 POSTROUTING 改写源地址）
# 注意：-s 不能覆盖池前缀，link-local/multicast 由模块自动跳过
ip6tables -t mangle -A POSTROUTING -o "$IF" -s "${SNAT_SRC}" -j NAT --snat

# 回包经 DNAT 后进 INPUT，需显式放行（尤其在未使用 conntrack 时）
ip6tables -I INPUT 1 -j ACCEPT

echo "  规则已添加:"
ip6tables -t mangle -L PREROUTING  -n --line-numbers 2>/dev/null | head -5
ip6tables -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | head -5

# ---------- Step 5: 验证 ----------
echo "[5/5] 验证连通性..."
echo ""

echo ">>> curl -6 ipv6.ip.sb"
RESULT=$(curl -6 -s ipv6.ip.sb --connect-timeout 5 --max-time 10 2>&1) || true
echo "  出口 IP: $RESULT"
echo ""

echo ">>> /proc/net/NAT/statistics"
cat /proc/net/NAT/statistics 2>/dev/null || true
echo ""

echo ">>> /proc/net/NAT/sessions"
cat /proc/net/NAT/sessions 2>/dev/null || true
echo ""

# ---------- 提示 ----------
cat <<'TIPS'
=== 常用运维命令 ===

# 查看会话与统计
cat /proc/net/NAT/sessions
cat /proc/net/NAT/statistics

# 开启/关闭详细日志（无需重载模块）
echo 1 > /sys/module/xt_NAT/parameters/nat_log_verbose
echo 0 > /sys/module/xt_NAT/parameters/nat_log_verbose

# 查看日志
dmesg | grep xt_NAT

# 清理（卸载模块会清空所有会话）
ip6tables -t mangle -F PREROUTING
ip6tables -t mangle -F POSTROUTING
modprobe -r xt_NAT
TIPS
