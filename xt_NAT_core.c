/*
 * xt_NAT_core.c - Module shell: global state, GC scheduler, proc/stats, init/exit
 *
 * Defines module parameters, per-CPU stats, GC timer dispatch,
 * /proc/net/NAT/statistics, and module_init/module_exit.
 */
#include "xt_NAT_internal.h"

/* ---- module parameters ---- */

static char nat_pool_buf[128] = "127.0.0.1-127.0.0.1";
static char *nat_pool = nat_pool_buf;
module_param(nat_pool, charp, 0444);
MODULE_PARM_DESC(nat_pool, "NAT pool range (addr_start-addr_end), default = 127.0.0.1-127.0.0.1");

static char nat_pool6_buf[256] = "fd00::1-fd00::1";
static char *nat_pool6 = nat_pool6_buf;
module_param(nat_pool6, charp, 0444);
MODULE_PARM_DESC(nat_pool6, "IPv6 NAT pool range (addr_start-addr_end), default = fd00::1-fd00::1");

int nat_hash_size = 1024 * 1024;
module_param(nat_hash_size, int, 0444);
MODULE_PARM_DESC(nat_hash_size, "nat hash size, default = 256k");

bool nat_log_verbose;
module_param(nat_log_verbose, bool, 0644);
MODULE_PARM_DESC(nat_log_verbose, "Log every NAT/NAT6 session assignment (default = false)");

static char nf_dest_buf[128] = "";
static char *nf_dest = nf_dest_buf;
module_param(nf_dest, charp, 0444);
MODULE_PARM_DESC(nf_dest, "Netflow v5 collectors (addr1:port1[,addr2:port2]), default = none");

/* ---- shared globals ---- */

DEFINE_PER_CPU(struct xt_nat_stat, xt_nat_stats);
u32  nat_hash_rnd __read_mostly;
bool nat_exiting;

static DEFINE_SPINLOCK(sessions_timer_lock);
static struct timer_list sessions_cleanup_timer;
static u32 nat_htable_vector;
static u32 nat6_htable_vector;
static struct proc_dir_entry *proc_net_nat;

/* ---- GC timer callback ---- */

static void sessions_cleanup_timer_callback(struct timer_list *timer)
{
	u32 v4_start = 0, v4_end = 0;
	u32 v6_start = 0, v6_end = 0;

	(void)timer;

	spin_lock_bh(&sessions_timer_lock);

	if (READ_ONCE(nat_exiting)) {
		spin_unlock_bh(&sessions_timer_lock);
		return;
	}

	/* IPv4 segment calculation */
	{
		u32 chunk = nat_hash_size / CLEANUP_SEGMENTS;
		if (chunk == 0)
			chunk = 1;
		if (nat_htable_vector >= CLEANUP_SEGMENTS) {
			v4_start = CLEANUP_SEGMENTS * (nat_hash_size / CLEANUP_SEGMENTS);
			v4_end = nat_hash_size;
			nat_htable_vector = 0;
		} else {
			v4_start = nat_htable_vector * chunk;
			v4_end = v4_start + chunk;
			nat_htable_vector++;
		}
		if (v4_start >= (u32)nat_hash_size) {
			v4_start = 0;
			v4_end = chunk;
			nat_htable_vector = 0;
		}
		if (v4_end > (u32)nat_hash_size)
			v4_end = nat_hash_size;
	}

	/* IPv6 segment calculation */
	{
		u32 v6_chunk = nat6_hash_size / CLEANUP_SEGMENTS;
		if (v6_chunk == 0)
			v6_chunk = 1;
		if (nat6_htable_vector >= CLEANUP_SEGMENTS) {
			v6_start = CLEANUP_SEGMENTS * (nat6_hash_size / CLEANUP_SEGMENTS);
			v6_end = nat6_hash_size;
			nat6_htable_vector = 0;
		} else {
			v6_start = nat6_htable_vector * v6_chunk;
			v6_end = v6_start + v6_chunk;
			nat6_htable_vector++;
		}
		if (v6_start >= (u32)nat6_hash_size) {
			v6_start = 0;
			v6_end = v6_chunk;
			nat6_htable_vector = 0;
		}
		if (v6_end > (u32)nat6_hash_size)
			v6_end = nat6_hash_size;
	}

	mod_timer(&sessions_cleanup_timer, jiffies + msecs_to_jiffies(100));
	spin_unlock_bh(&sessions_timer_lock);

	xt_nat_gc_ipv4(v4_start, v4_end);
	xt_nat_gc_ipv6(v6_start, v6_end);
}

/* ---- proc / statistics ---- */

static u64 xt_nat_stat_sum(size_t offset)
{
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += *(u64 *)((char *)per_cpu_ptr(&xt_nat_stats, cpu) + offset);
	return sum;
}

static int stat_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Active NAT sessions: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, sessions_active)));
	seq_printf(m, "Tried NAT sessions: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, sessions_tried)));
	seq_printf(m, "Created NAT sessions: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, sessions_created)));
	seq_printf(m, "DNAT dropped pkts: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, dnat_dropped)));
	seq_printf(m, "Early dropped sessions: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, early_drops)));
	seq_printf(m, "Fragmented pkts: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, frags)));
	seq_printf(m, "Related ICMP pkts: %llu\n",
		   xt_nat_stat_sum(offsetof(struct xt_nat_stat, related_icmp)));
	return 0;
}

static int stat_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, stat_seq_show, NULL);
}

static const XT_NAT_PROC_OPS stat_seq_fops = {
	XT_NAT_PROC_OPEN    = stat_seq_open,
	XT_NAT_PROC_READ    = seq_read,
	XT_NAT_PROC_LSEEK   = seq_lseek,
	XT_NAT_PROC_RELEASE = single_release,
};

/* ---- xt_target registrations ---- */

static struct xt_target nat_tg_reg __read_mostly = {
	.name       = "NAT",
	.revision   = 0,
	.family     = NFPROTO_IPV4,
	.hooks      = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) |
		      (1 << NF_INET_POST_ROUTING),
	.target     = nat_tg,
	.targetsize = sizeof(struct xt_nat_tginfo),
	.me         = THIS_MODULE,
};

static struct xt_target nat_tg6_reg __read_mostly = {
	.name       = "NAT",
	.revision   = 0,
	.family     = NFPROTO_IPV6,
	.hooks      = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) |
		      (1 << NF_INET_POST_ROUTING),
	.target     = nat_tg6,
	.targetsize = sizeof(struct xt_nat_tginfo),
	.me         = THIS_MODULE,
};

/* ---- module init / exit ---- */

static int __init nat_tg_init(void)
{
	int ret;

	printk(KERN_INFO "Module xt_NAT loaded\n");
	printk(KERN_INFO "xt_NAT DEBUG: NAT hash size: %d\n", nat_hash_size);

	nat_hash_rnd = get_random_u32();

	ret = xt_nat_ipv4_init(nat_pool);
	if (ret)
		return ret;

	ret = xt_nat_ipv6_init(nat_pool6);
	if (ret)
		goto err_ipv6;

	xt_nat_netflow_init(nf_dest);

	proc_net_nat = proc_mkdir("NAT", init_net.proc_net);
	proc_create("statistics", 0644, proc_net_nat, &stat_seq_fops);

	spin_lock_bh(&sessions_timer_lock);
	timer_setup(&sessions_cleanup_timer, sessions_cleanup_timer_callback, 0);
	mod_timer(&sessions_cleanup_timer, jiffies + msecs_to_jiffies(1000));
	spin_unlock_bh(&sessions_timer_lock);

	ret = xt_register_target(&nat_tg_reg);
	if (ret)
		goto err_reg4;

	ret = xt_register_target(&nat_tg6_reg);
	if (ret)
		goto err_reg6;

	return 0;

err_reg6:
	xt_unregister_target(&nat_tg_reg);
err_reg4:
	WRITE_ONCE(nat_exiting, true);
	del_timer_sync(&sessions_cleanup_timer);
	remove_proc_entry("statistics", proc_net_nat);
	proc_remove(proc_net_nat);
	xt_nat_netflow_exit();
	xt_nat_ipv6_exit();
err_ipv6:
	xt_nat_ipv4_exit();
	return ret;
}

static void __exit nat_tg_exit(void)
{
	xt_unregister_target(&nat_tg6_reg);
	xt_unregister_target(&nat_tg_reg);

	WRITE_ONCE(nat_exiting, true);

	del_timer_sync(&sessions_cleanup_timer);

	remove_proc_entry("statistics", proc_net_nat);
	proc_remove(proc_net_nat);

	synchronize_rcu();
	rcu_barrier();

	xt_nat_netflow_exit();
	xt_nat_ipv6_exit();
	xt_nat_ipv4_exit();

	printk(KERN_INFO "Module xt_NAT unloaded\n");
}

module_init(nat_tg_init);
module_exit(nat_tg_exit);

MODULE_DESCRIPTION("Xtables: Full Cone NAT");
MODULE_AUTHOR("Andrei Sharaev <andr.sharaev@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_NAT");
MODULE_ALIAS("ip6t_NAT");
