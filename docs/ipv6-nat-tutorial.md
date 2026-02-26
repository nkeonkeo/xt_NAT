# xt_NAT IPv6 NAT 使用指南

## 概述

xt_NAT 是一个 Linux 内核模块，为 IPv4 和 IPv6 提供 Full Cone NAT。每个新连接从配置的地址池中**随机选取**一个出口 IPv6 地址，会话记录在内核中，回包自动做 DNAT 还原。

## 模块参数

| 参数 | 类型 | 权限 | 说明 |
|------|------|------|------|
| `nat_pool` | string | 0444 | IPv4 地址池范围（`start-end`，必填） |
| `nat_pool6` | string | 0444 | IPv6 地址池范围（`start-end`） |
| `nat_hash_size` | int | 0444 | IPv4 会话哈希表大小（默认 256k） |
| `users_hash_size` | int | 0444 | 用户哈希表大小（默认 4k） |
| `nat_log_verbose` | bool | 0644 | 打印每次 NAT/NAT6 会话分配日志（默认 false，可运行时切换） |
| `nf_dest` | string | 0444 | NetFlow v5 采集器地址（`addr:port`） |

## 可用的 ip6tables 链

xt_NAT 内核 target 注册了 `PRE_ROUTING`、`FORWARD`、`POST_ROUTING` 三个 hook，**未注册 `LOCAL_OUT`**。

| 表 | 链 | 可用操作 |
|----|-----|---------|
| raw | PREROUTING | DNAT |
| mangle | PREROUTING | DNAT |
| mangle | FORWARD | SNAT / DNAT（仅转发） |
| mangle | POSTROUTING | SNAT |
| nat | PREROUTING | DNAT |
| nat | POSTROUTING | SNAT |
| filter | FORWARD | SNAT / DNAT（仅转发） |
| **任何表** | **OUTPUT** | **不可用**（未注册 LOCAL_OUT） |

## 快速开始

### 1. 编译安装

```bash
make && sudo make install && sudo depmod -a
```

### 2. 加载模块

```bash
sudo modprobe xt_NAT \
  nat_pool=198.51.100.10-198.51.100.20 \
  nat_pool6=2001:db8:1:0:0:0:0:0-2001:db8:1:ffff:ffff:ffff:ffff:ffff
```

`nat_pool` 为必填参数（即使只用 IPv6）。`nat_pool6` 支持任意 start-end 范围，每个新会话从中随机选取一个地址。

确认加载成功：

```bash
cat /sys/module/xt_NAT/parameters/nat_pool6
```

### 3. 配置网络：路由与 NDP

回包的目的地址是池内 IP，必须让本机能接收到：

```bash
# 本地路由：让内核认为池前缀是"本地"地址，回包可进入 PREROUTING
sudo ip -6 route add local 2001:db8:1::/48 dev lo

# Proxy NDP：让本机代答池地址的邻居发现请求
sudo sysctl -w net.ipv6.conf.eth0.proxy_ndp=1
sudo ip -6 neigh add proxy 2001:db8:1:: dev eth0
```

> **注意**：不要把池地址加到出口接口上（`ip -6 addr add`），否则内核会优先选池地址做 curl/ping 的源地址，导致 SNAT 失效。

### 4. 添加 ip6tables 规则

```bash
# DNAT：仅匹配目的为池前缀的回包
sudo ip6tables -t mangle -A PREROUTING -d 2001:db8:1::/48 -j NAT --dnat

# SNAT：仅匹配源为内网前缀的出口包
sudo ip6tables -t mangle -A POSTROUTING -o eth0 -s 2001:db8:0::/48 -j NAT --snat
```

**关键要点**：

- **SNAT 必须加 `-s` 源前缀过滤**，不能匹配所有出口包。否则 link-local（fe80::）、池内地址等会被错误 SNAT。
- **DNAT 必须加 `-d` 池前缀过滤**，只处理目的地址在池范围内的回包。
- SNAT 的源前缀**不能包含池前缀**，否则已 SNAT 过的包会被重复处理。

可选: 添加 FORWARD

```bash
ip6tables -A FORWARD -i eth1 -o eth0 -j ACCEPT

# SNAT：匹配所有出口包
sudo ip6tables -t mangle -A POSTROUTING -o eth0 -j NAT --snat
```

将eth1上的流量转发到eth0出口

### 5. 验证

```bash
# 查看出口 IP（应显示池内地址）
curl -6 ipv6.ip.sb

# 查看会话与统计
cat /proc/net/NAT/sessions
cat /proc/net/NAT/statistics
```

### 6. 调试日志

默认不输出会话分配日志，需要时可动态开启：

```bash
# 开启详细日志
echo 1 > /sys/module/xt_NAT/parameters/nat_log_verbose

# 查看日志
dmesg | grep xt_NAT

# 关闭详细日志
echo 0 > /sys/module/xt_NAT/parameters/nat_log_verbose
```

## 转发场景（路由器/网关）

如果 NAT 主机作为路由器，内网客户端的流量经过 FORWARD 链：

```bash
# 开启 IPv6 转发
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# DNAT（PREROUTING，回包进来时改写目的）
sudo ip6tables -t mangle -A PREROUTING -d 2001:db8:1::/48 -j NAT --dnat

# SNAT（POSTROUTING，转发包出去时改写源）
sudo ip6tables -t mangle -A POSTROUTING -o eth0 -s fd00::/64 -j NAT --snat

# 放行转发
sudo ip6tables -A FORWARD -j ACCEPT
```

## 持久化配置

### 模块自动加载

```bash
echo xt_NAT | sudo tee /etc/modules-load.d/xt-nat.conf

cat <<'EOF' | sudo tee /etc/modprobe.d/xt-nat.conf
options xt_NAT nat_pool=198.51.100.10-198.51.100.20 nat_pool6=2001:db8:1:0:0:0:0:0-2001:db8:1:ffff:ffff:ffff:ffff:ffff
EOF
```

### 防火墙规则持久化

使用发行版的方式保存（如 `iptables-persistent`、systemd unit 等）。

## 排障清单

| 现象 | 排查 |
|------|------|
| **modprobe 失败** | `dmesg \| tail`；确认 `nat_pool6` 格式为 `start-end` 且 start ≤ end |
| **curl 超时 / 无回包** | 1) 池前缀是否路由到本机：`ip -6 route get <pool_addr>` 应显示 local<br>2) proxy NDP 是否生效：`ip -6 neigh show proxy`<br>3) DNAT 规则是否加了 `-d 池前缀` |
| **SNAT 改写了 NDP / link-local** | SNAT 规则必须加 `-s 内网前缀`，不能匹配所有出口包 |
| **DNAT dropped 增加但无会话** | 回包到了但找不到会话——可能会话已过期或源端口不匹配。开启 `nat_log_verbose=1` 查看详细日志 |
| **地址不够随机** | 确认池范围够大；`nat_pool6_range_bits` 决定随机位数 |
| **Created sessions = 0** | SNAT 规则未匹配——检查 `-s` 前缀是否覆盖本机/内网地址，且不包含池地址 |
| **池地址被当作源 SNAT 自身** | SNAT 源前缀不能包含池前缀；模块内已有防护（跳过源在池内的包），但规则层也应避免 |
