cmd_/root/xt_NAT/Module.symvers :=  sed 's/ko$$/o/'  /root/xt_NAT/modules.order | scripts/mod/modpost -m      -o /root/xt_NAT/Module.symvers -e -i Module.symvers -T - 
