# xt_NAT
## Description
This Full Cone NAT xtables module was developed as a replace for the conntrack NAT to provide Assymetric NAT features on Linux systems that can be used as a Carrier Grade NAT in small ISP networks.

It allows to have 40Gbps NAT on commodity servers like 2*Xeon E5-2698 v3 @ 2.30GHz (2 x 16 Cores) with Intel X710/XL710/X540 10G adapters.

Compatibility tested with Linux Kernel 3.18 and 4.1
## Features
* PAT/NAPT work mode - translates many users into a single NAT IP
* Assymetric (Full Cone) NAT - allows inbound connections from any source IP address and any source port, as long as the NAT rule exists
* Support of TCP/UDP/ICMP/Generic IP protocols
* Random IP Pool mode - each new NAT session gets a random NAT IP from configured pool
* Endpoint Independent Mapping - the same NAT_IP:NAT_Port mapping is used for traffic sent from same subscriber IP
address and port to any external IP address and port
* Hairpinning - allows communication between two internal subscribers or internal hosts using the NAT IP
* User quotas support. Default value is 1000 max connections for each user (for each protocol independly)
* No ALGs for FTP/SIP/PPTP are implemented
* NAT events export using Netflow v5
* NAT statistics via /proc interface

## Installation
Install build dependencies first (Ubuntu example):
```
$ sudo apt-get update
$ sudo apt-get install -y build-essential libxtables-dev linux-headers-generic
```

If running kernel headers are unavailable (common in containers), the Makefile will automatically use the newest installed `/lib/modules/*/build` directory.

```
$ make
$ sudo make install
$ sudo depmod -a
```

## Usage
### NAT functionality
* Define NAT Pool for the xt_NAT module:
```
$ sudo modprobe xt_NAT nat_pool=<Start IP>-<End IP>
```
* Disable conntrack for the traffic that handled by the xt_NAT module:
```
$ sudo iptables -t raw -A PREROUTING -s <Users Net> -j CT --notrack
$ sudo iptables -t raw -A PREROUTING -d <NAT Pool Net> -j CT --notrack
```
* Add iptables rule to use xt_NAT module for User's traffic (from Internet to Users):
```
$ sudo iptables -t raw -A PREROUTING -d <NAT Pool Net>  -j NAT --dnat
$ sudo iptables -A FORWARD -d <Users Net> -i <Uplink iface> -o <Downlink iface> -j ACCEPT
```
* Add iptables rule to use xt_NAT module for User's traffic (from Internet to Users):
```
$ sudo iptables -A FORWARD -s <Users Net> -i <Downlink iface> -o <Uplink iface> -j NAT –snat
```

### IPv6 / ip6tables (experimental)
* Define IPv6 NAT Pool together with IPv4 pool:
```
$ sudo modprobe xt_NAT nat_pool=<IPv4-Start>-<IPv4-End> nat_pool6=<IPv6-Start>-<IPv6-End>
```
* Add ip6tables rules:
```
$ sudo ip6tables -t raw -A PREROUTING -d <IPv6 NAT Pool Prefix> -j NAT --dnat
$ sudo ip6tables -A FORWARD -s <Users IPv6 Prefix> -j NAT --snat
```
* Current IPv6 pool parser supports ranges that vary only in the lower 32 bits of the address.
* Full tutorial and complete example (including `fe80::/64` -> `2404:6800::/32` planning) is available at:
  * `docs/ipv6-nat-tutorial.md`

### NAT Events Export
Just add ``nf_dest`` option with a list of the Netflow v5 collectors to the xt_NAT module parameters:
```
$ sudo modprobe xt_NAT nat_pool=<Start IP>-<End IP> nf_dest=127.0.0.1:2055
```
## NAT Statistics
NAT statistics are available via the ```/proc/net/NAT/*``` directory:
* /proc/net/NAT/sessions - NAT sessions for all users
* /proc/net/NAT/users - NAT users with their NAT IPs
* /proc/net/NAT/statistics - internal counters 
