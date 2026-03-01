cmd_/root/xt_NAT/xt_NAT.ko := ld -r -m elf_x86_64 -z noexecstack --build-id=sha1  -T arch/x86/module.lds -o /root/xt_NAT/xt_NAT.ko /root/xt_NAT/xt_NAT.o /root/xt_NAT/xt_NAT.mod.o;  true
