# IPv6 NAT Tutorial (xt_NAT, ip6tables)

This tutorial shows a full IPv6 SNAT/DNAT setup for `xt_NAT` using:

- Inside network: `fe80::/64` (as requested)
- Public pool prefix: `2404:6800::/32`

## Important notes before you start

1. The current `xt_NAT` IPv6 pool parser accepts `nat_pool6=<start>-<end>` and supports ranges that vary only in the **lowest 32 bits**.
2. Because of that, for a `/32` public prefix you must choose a usable **/96 slice** from it.
3. `fe80::/64` is link-local. It works for lab/testing, but production usually uses ULA/GUA on the inside.
4. Your upstream network must route the chosen IPv6 NAT pool to this box (or provide equivalent neighbor/proxy behavior).

## Example address plan

Use this /96 slice from `2404:6800::/32`:

- Pool CIDR: `2404:6800:0:0:0:0:0:0/96`
- Pool start: `2404:6800:0:0:0:0:0:1`
- Pool end: `2404:6800:0:0:0:0:ffff:fffe`

Inside clients:

- `fe80::/64`

Interfaces:

- LAN: `eth1`
- WAN: `eth0`

## 1) Build and install

```bash
make
sudo make install
sudo depmod -a
```

## 2) Enable IPv6 forwarding

```bash
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.default.forwarding=1
```

Persist if needed:

```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-xt-nat-ipv6.conf
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
sudo sysctl --system
```

## 3) Load xt_NAT with IPv4 + IPv6 pools

`nat_pool` is mandatory in current module init path, so keep a valid IPv4 range even if you only test IPv6.

```bash
sudo modprobe xt_NAT \
  nat_pool=198.51.100.10-198.51.100.20 \
  nat_pool6=2404:6800:0:0:0:0:0:1-2404:6800:0:0:0:0:ffff:fffe
```

## 4) Configure ip6tables rules

### 4.1 Disable conntrack for traffic handled by xt_NAT

```bash
sudo ip6tables -t raw -A PREROUTING -s fe80::/64 -j CT --notrack
sudo ip6tables -t raw -A PREROUTING -d 2404:6800:0:0::/96 -j CT --notrack
```

### 4.2 DNAT path (outside -> inside, based on NAT session table)

```bash
sudo ip6tables -t raw -A PREROUTING -d 2404:6800:0:0::/96 -j NAT --dnat
```

### 4.3 SNAT path (inside -> outside, random IPv6 per new session)

```bash
sudo ip6tables -A FORWARD -s fe80::/64 -i eth1 -o eth0 -j NAT --snat
sudo ip6tables -A FORWARD -d fe80::/64 -i eth0 -o eth1 -j ACCEPT
```

## 5) Verify

Start traffic from an inside host, for example:

```bash
ping6 -c 3 2001:4860:4860::8888
curl -6 https://ifconfig.co
```

On the NAT host:

```bash
sudo ip6tables -t raw -vnL
sudo ip6tables -vnL FORWARD
sudo cat /proc/net/NAT/sessions
sudo cat /proc/net/NAT/statistics
```

You should see NAT sessions where each new flow may use a different random `2404:6800:0:0::/96` source IPv6.

## 6) Persistence example

Use `/etc/modules-load.d/xt-nat.conf`:

```bash
echo xt_NAT | sudo tee /etc/modules-load.d/xt-nat.conf
```

Use `/etc/modprobe.d/xt-nat.conf`:

```bash
cat <<'EOF' | sudo tee /etc/modprobe.d/xt-nat.conf
options xt_NAT nat_pool=198.51.100.10-198.51.100.20 nat_pool6=2404:6800:0:0:0:0:0:1-2404:6800:0:0:0:0:ffff:fffe
EOF
```

Persist firewall rules with your distro method (`iptables-persistent`, systemd unit, or nftables wrapper).

## 7) Troubleshooting checklist

1. `modprobe xt_NAT` fails:
   - Check `dmesg | tail -n 100`
   - Verify `nat_pool6` format is `start-end` and stays inside one /96 slice.
2. No return traffic:
   - Ensure upstream routes `2404:6800:0:0::/96` to this host.
   - Verify DNAT PREROUTING rule is in `raw` table.
3. Rules not matching:
   - Confirm interface names (`eth0`/`eth1`) and inside prefix are correct.
4. No sessions created:
   - Check `/proc/net/NAT/statistics` counters and `ip6tables -v` packet counters.
