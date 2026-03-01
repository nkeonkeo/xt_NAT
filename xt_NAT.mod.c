#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd542439, "__ipv6_addr_type" },
	{ 0xff2c8e5d, "proc_create" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x609bcd98, "in6_pton" },
	{ 0x69acdf38, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0x44f0ad9, "get_random_u16" },
	{ 0x39d9014b, "seq_lseek" },
	{ 0x82ee90dc, "timer_delete_sync" },
	{ 0x7657f929, "kmem_cache_create" },
	{ 0xb19a5453, "__per_cpu_offset" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x92997ed8, "_printk" },
	{ 0xac5fcec0, "in4_pton" },
	{ 0xa19b956, "__stack_chk_fail" },
	{ 0xe46021ca, "_raw_spin_unlock_bh" },
	{ 0xe7a1f35a, "ipv6_skip_exthdr" },
	{ 0xa916b694, "strnlen" },
	{ 0xb236fada, "kmem_cache_alloc" },
	{ 0x599fb41c, "kvmalloc_node" },
	{ 0x119221dc, "xt_register_target" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0x31ae38f1, "init_net" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0xc38c83b8, "mod_timer" },
	{ 0xbfac1942, "kmem_cache_free" },
	{ 0x72f64423, "skb_ensure_writable" },
	{ 0x9ec6ca96, "ktime_get_real_ts64" },
	{ 0x53a1e8d9, "_find_next_bit" },
	{ 0x449ad0a7, "memcmp" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0x37befc70, "jiffies_to_msecs" },
	{ 0x8518a4a6, "_raw_spin_trylock_bh" },
	{ 0xae1c0cf4, "proc_mkdir" },
	{ 0x9e683f75, "__cpu_possible_mask" },
	{ 0xc47f4975, "param_ops_charp" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x17de3d5, "nr_cpu_ids" },
	{ 0x5d63040b, "__pskb_pull_tail" },
	{ 0x4d9d0f1b, "proc_remove" },
	{ 0xc71e8d47, "inet_proto_csum_replace16" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x6c99329b, "seq_read" },
	{ 0x1ac5d3cb, "strcspn" },
	{ 0x4629334c, "__preempt_count" },
	{ 0x28aa6a67, "call_rcu" },
	{ 0x999e8297, "vfree" },
	{ 0xdf521442, "_find_next_zero_bit" },
	{ 0x7fdf8d24, "sock_create_kern" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x46aefd7, "param_ops_bool" },
	{ 0x182a0dee, "inet_proto_csum_replace4" },
	{ 0xccd422e5, "remove_proc_entry" },
	{ 0xac8427d8, "seq_printf" },
	{ 0xd36dc10c, "get_random_u32" },
	{ 0x20000329, "simple_strtoul" },
	{ 0xc3690fc, "_raw_spin_lock_bh" },
	{ 0x62b9cbb8, "sock_release" },
	{ 0xdc5d0c58, "single_release" },
	{ 0x1b6314fd, "in_aton" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0xc29bf967, "strspn" },
	{ 0x60a13e90, "rcu_barrier" },
	{ 0xbe3c9997, "param_ops_int" },
	{ 0x7aa1756e, "kvfree" },
	{ 0x8c694071, "single_open" },
	{ 0x349cba85, "strchr" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x5d1190fa, "kernel_sendmsg" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x54c1dc64, "kmem_cache_destroy" },
	{ 0xef49b30a, "xt_unregister_target" },
	{ 0x160c03af, "module_layout" },
};

MODULE_INFO(depends, "x_tables");

