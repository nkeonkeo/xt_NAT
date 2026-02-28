#ifndef XT_NAT_INTERNAL_H
#define XT_NAT_INTERNAL_H

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/bitmap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/timekeeping.h>
#include <linux/percpu.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include "compat.h"
#include "xt_NAT.h"

/* ---------------- compat macros ---------------- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define XT_NAT_PROC_OPS	struct proc_ops
#define XT_NAT_PROC_OPEN	.proc_open
#define XT_NAT_PROC_READ	.proc_read
#define XT_NAT_PROC_LSEEK	.proc_lseek
#define XT_NAT_PROC_RELEASE	.proc_release
#else
#define XT_NAT_PROC_OPS	struct file_operations
#define XT_NAT_PROC_OPEN	.open
#define XT_NAT_PROC_READ	.read
#define XT_NAT_PROC_LSEEK	.llseek
#define XT_NAT_PROC_RELEASE	.release
#endif

/* ---------------- constants ---------------- */

#define FLAG_REPLIED		(1 << 0)
#define FLAG_TCP_FIN		(1 << 1)

#define TCP_SYN_ACK		0x12
#define TCP_FIN_RST		0x05

#define EARLY_DROP_SCAN_MAX	16
#define EARLY_DROP_JIFFIES_MAX	(10 * HZ)

#define NAT_TIMEOUT_EST		(30 * HZ)
#define NAT_TIMEOUT_SHORT	(3 * HZ)
#define NAT_TIMEOUT_CLOSE	(1 * HZ)

#define PORT_BITMAP_BITS	65536
#define PORT_BITMAP_PROTOS	3   /* TCP=0, UDP=1, ICMP=2 */

#define PORT6_BITMAP_PROTOS	3   /* TCP=0, UDP=1, ICMPv6=2 */
#define PORT6_BM_MEM_LIMIT	(4ULL * 1024 * 1024 * 1024)
#define PORT6_BM_STRIDE		BITS_TO_LONGS(PORT_BITMAP_BITS)

#define NAT6_CREATE_LOCK_BITS	10
#define NAT6_CREATE_LOCK_SIZE	(1 << NAT6_CREATE_LOCK_BITS)

#define CLEANUP_SEGMENTS	10

/* ---------------- data structures ---------------- */

struct xt_nat_stat {
	u64 sessions_active;
	u64 sessions_tried;
	u64 sessions_created;
	u64 dnat_dropped;
	u64 frags;
	u64 related_icmp;
	u64 early_drops;
};

struct netflow_sock {
	struct list_head list;
	struct socket *sock;
	struct sockaddr_storage addr;
};

struct xt_nat_htable {
	uint32_t use;
	spinlock_t lock;
	struct hlist_head session;
};

struct nat_htable_ent {
	struct hlist_node list_node;
	uint8_t  proto;
	uint32_t addr;
	uint16_t port;
	struct nat_session *data;
	struct rcu_head rcu;
};

struct nat_session {
	unsigned long timeout;
	uint32_t in_addr;
	uint16_t in_port;
	uint32_t out_addr;
	uint16_t out_port;
	uint8_t  flags;
};

struct nat6_session_data {
	unsigned long timeout;
	struct in6_addr in_addr;
	struct in6_addr out_addr;
	uint16_t in_port;
	uint16_t out_port;
	uint8_t  flags;
};

struct nat6_htable_ent {
	struct hlist_node list_node;
	uint8_t  proto;
	uint16_t port;
	struct in6_addr addr;
	struct nat6_session_data *data;
	struct hlist_node addr_list_node;
	struct rcu_head rcu;
};

/* ---------------- extern globals (core.c) ---------------- */

DECLARE_PER_CPU(struct xt_nat_stat, xt_nat_stats);
extern bool nat_log_verbose;
extern int  nat_hash_size;
extern u32  nat_hash_rnd;
extern bool nat_exiting;

/* ---------------- extern globals (ipv4.c) ---------------- */

extern u_int32_t nat_pool_start;
extern u_int32_t nat_pool_end;
extern unsigned long **port_bitmaps;

/* ---------------- extern globals (ipv6.c) ---------------- */

extern struct in6_addr nat_pool6_start, nat_pool6_end, nat_pool6_range;
extern u8 nat_pool6_range_bits;
extern int nat6_hash_size;
extern unsigned long *port6_bm_base;

/* ---------------- inline utility functions ---------------- */

static inline u_int32_t get_pool_size(void)
{
	return ntohl(nat_pool_end) - ntohl(nat_pool_start) + 1;
}

static inline u_int32_t
get_hash_nat_ent(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
	return reciprocal_scale(jhash_3words((u32)proto, addr, (u32)port,
					     nat_hash_rnd), nat_hash_size);
}

static inline u_int32_t
get_hash_nat6_ent(const uint8_t proto, const struct in6_addr *addr,
		  const uint16_t port)
{
	u32 a = jhash2((const u32 *)addr->s6_addr, 4, nat_hash_rnd ^ (u32)proto);
	return reciprocal_scale(jhash_2words(a, (u32)port, nat_hash_rnd),
				nat6_hash_size);
}

static inline u_int32_t
get_hash_nat6_addr(const uint8_t proto, const struct in6_addr *addr)
{
	u32 a = jhash2((const u32 *)addr->s6_addr, 4, nat_hash_rnd ^ (u32)proto);
	return reciprocal_scale(a, nat6_hash_size);
}

static inline unsigned int nat6_addr_lock_hash(const struct in6_addr *addr)
{
	return jhash2((const u32 *)addr->s6_addr, 4, nat_hash_rnd)
		& (NAT6_CREATE_LOCK_SIZE - 1);
}

static inline int proto_to_bitmap_idx(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return 0;
	case IPPROTO_UDP:  return 1;
	case IPPROTO_ICMP: return 2;
	default:           return -1;
	}
}

static inline unsigned long *get_port_bitmap(unsigned int nataddr_id,
					     uint8_t proto)
{
	int idx = proto_to_bitmap_idx(proto);
	if (idx < 0 || !port_bitmaps)
		return NULL;
	return port_bitmaps[nataddr_id * PORT_BITMAP_PROTOS + idx];
}

static inline int proto_to_bitmap6_idx(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:    return 0;
	case IPPROTO_UDP:    return 1;
	case IPPROTO_ICMPV6: return 2;
	default:             return -1;
	}
}

static inline int in6_addr_cmp_raw(const struct in6_addr *a,
				   const struct in6_addr *b)
{
	return memcmp(a->s6_addr, b->s6_addr, sizeof(a->s6_addr));
}

static inline void in6_addr_sub_raw(const struct in6_addr *a,
				    const struct in6_addr *b,
				    struct in6_addr *res)
{
	int i, borrow = 0;

	for (i = 15; i >= 0; i--) {
		int diff = (int)a->s6_addr[i] - (int)b->s6_addr[i] - borrow;
		if (diff < 0) {
			diff += 256;
			borrow = 1;
		} else {
			borrow = 0;
		}
		res->s6_addr[i] = (u8)diff;
	}
}

static inline void in6_addr_add_raw(const struct in6_addr *a,
				    const struct in6_addr *b,
				    struct in6_addr *res)
{
	int i, carry = 0;

	for (i = 15; i >= 0; i--) {
		int sum = (int)a->s6_addr[i] + (int)b->s6_addr[i] + carry;
		res->s6_addr[i] = (u8)(sum & 0xff);
		carry = sum >> 8;
	}
}

static inline bool in6_addr_in_pool6_range(const struct in6_addr *addr)
{
	return in6_addr_cmp_raw(&nat_pool6_start, addr) <= 0 &&
	       in6_addr_cmp_raw(addr, &nat_pool6_end) <= 0;
}

static inline u32 get_pool6_addr_idx(const struct in6_addr *addr)
{
	struct in6_addr diff;

	in6_addr_sub_raw(addr, &nat_pool6_start, &diff);
	return ((u32)diff.s6_addr[12] << 24) | ((u32)diff.s6_addr[13] << 16) |
	       ((u32)diff.s6_addr[14] << 8)  | (u32)diff.s6_addr[15];
}

static inline unsigned long *get_port6_bitmap(const struct in6_addr *addr,
					      uint8_t proto)
{
	int idx = proto_to_bitmap6_idx(proto);
	u32 addr_idx;
	u64 offset;

	if (idx < 0 || !port6_bm_base)
		return NULL;
	addr_idx = get_pool6_addr_idx(addr);
	offset = ((u64)addr_idx * PORT6_BITMAP_PROTOS + idx) * PORT6_BM_STRIDE;
	return port6_bm_base + offset;
}

/* ---------------- cross-module function prototypes ---------------- */

/* xt_NAT_netflow.c */
void netflow_export_flow_v5(const uint8_t proto, const u_int32_t useraddr,
			    const uint16_t userport, const u_int32_t nataddr,
			    const uint16_t natport, const int flags);
int  xt_nat_netflow_init(const char *dest);
void xt_nat_netflow_exit(void);

/* xt_NAT_ipv4.c */
int  xt_nat_ipv4_init(const char *pool_str);
void xt_nat_ipv4_exit(void);
void xt_nat_gc_ipv4(u32 start, u32 end);
unsigned int nat_tg(struct sk_buff *skb, const struct xt_action_param *par);

/* xt_NAT_ipv6.c */
int  xt_nat_ipv6_init(const char *pool6_str);
void xt_nat_ipv6_exit(void);
void xt_nat_gc_ipv6(u32 start, u32 end);
unsigned int nat_tg6(struct sk_buff *skb, const struct xt_action_param *par);

#endif /* XT_NAT_INTERNAL_H */
