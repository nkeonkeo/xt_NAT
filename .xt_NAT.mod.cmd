cmd_/root/xt_NAT/xt_NAT.mod := printf '%s\n'   xt_NAT_core.o xt_NAT_ipv4.o xt_NAT_ipv6.o xt_NAT_netflow.o | awk '!x[$$0]++ { print("/root/xt_NAT/"$$0) }' > /root/xt_NAT/xt_NAT.mod
