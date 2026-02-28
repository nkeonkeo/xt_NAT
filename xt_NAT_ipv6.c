/*
 * xt_NAT_ipv6.c - IPv6 session management, data path, and garbage collection
 *
 * Pool6 parse, htable6 create/remove, bitmap6 create/remove, lookup, port search,
 * session create/evict, early drop, nat_tg6() data path, per-segment GC.
 */
#include "xt_NAT_internal.h"

/* ---- globals owned by this file ---- */

struct in6_addr nat_pool6_start __read_mostly;
struct in6_addr nat_pool6_end __read_mostly;
struct in6_addr nat_pool6_range __read_mostly;
u8  nat_pool6_range_bits __read_mostly;
int nat6_hash_size __read_mostly = 64 * 1024;

static struct xt_nat_htable *ht6_inner __read_mostly;
static struct xt_nat_htable *ht6_outer __read_mostly;
static struct xt_nat_htable *ht6_outer_by_addr __read_mostly;
static spinlock_t create_session6_lock[NAT6_CREATE_LOCK_SIZE] __cacheline_aligned_in_smp;

static struct kmem_cache *nat6_session_data_cachep __read_mostly;
static struct kmem_cache *nat6_htable_ent_cachep __read_mostly;

/* ---- helpers ---- */

static void nat6_ent_rcu_free(struct rcu_head *head)
{
	kmem_cache_free(nat6_htable_ent_cachep,
			container_of(head, struct nat6_htable_ent, rcu));
}

static u8 in6_addr_bit_width(const struct in6_addr *addr)
{
	int i;
	u8 bit;

	for (i = 0; i < 16; i++) {
		u8 v = addr->s6_addr[i];
		if (!v)
			continue;
		for (bit = 0; bit < 8; bit++) {
			if (v & (0x80 >> bit))
				return (u8)(128 - (i * 8 + bit));
		}
	}
	return 0;
}

static int parse_nat_pool6(const char *pool6_str)
{
	char start_buf[128] = { 0 };
	char end_buf[128] = { 0 };
	const char *sep;
	size_t left_len, right_len;

	sep = strchr(pool6_str, '-');
	if (!sep)
		return -EINVAL;

	left_len = sep - pool6_str;
	right_len = strnlen(sep + 1, sizeof(end_buf) - 1);
	if (left_len == 0 || left_len >= sizeof(start_buf))
		return -EINVAL;
	if (right_len == 0 || right_len >= sizeof(end_buf))
		return -EINVAL;

	memcpy(start_buf, pool6_str, left_len);
	memcpy(end_buf, sep + 1, right_len);

	if (!in6_pton(start_buf, -1, nat_pool6_start.s6_addr, -1, NULL))
		return -EINVAL;
	if (!in6_pton(end_buf, -1, nat_pool6_end.s6_addr, -1, NULL))
		return -EINVAL;
	if (in6_addr_cmp_raw(&nat_pool6_start, &nat_pool6_end) > 0)
		return -EINVAL;

	in6_addr_sub_raw(&nat_pool6_end, &nat_pool6_start, &nat_pool6_range);
	nat_pool6_range_bits = in6_addr_bit_width(&nat_pool6_range);

	return 0;
}

static inline void get_random_nat_addr6(struct in6_addr *addr)
{
	struct in6_addr offset;
	int leading_zero_bits, zero_bytes, zero_bits_remainder;

	if (nat_pool6_range_bits == 0) {
		*addr = nat_pool6_start;
		return;
	}

	do {
		get_random_bytes(offset.s6_addr, sizeof(offset.s6_addr));
		leading_zero_bits = 128 - nat_pool6_range_bits;
		zero_bytes = leading_zero_bits / 8;
		zero_bits_remainder = leading_zero_bits % 8;
		if (zero_bytes > 0)
			memset(offset.s6_addr, 0, zero_bytes);
		if (zero_bits_remainder)
			offset.s6_addr[zero_bytes] &= (u8)(0xFF >> zero_bits_remainder);
	} while (in6_addr_cmp_raw(&offset, &nat_pool6_range) > 0);

	in6_addr_add_raw(&nat_pool6_start, &offset, addr);

	if (unlikely(!in6_addr_in_pool6_range(addr))) {
		printk(KERN_WARNING "xt_NAT IPv6: generated address out of pool range, using pool start\n");
		*addr = nat_pool6_start;
	}
}

/* ---- hash table create / remove ---- */

static int nat6_htable_create(void)
{
	unsigned int sz;
	int i;

	sz = sizeof(struct xt_nat_htable) * nat6_hash_size;
	ht6_inner = kvzalloc(sz, GFP_KERNEL);
	if (!ht6_inner)
		return -ENOMEM;
	for (i = 0; i < nat6_hash_size; i++) {
		spin_lock_init(&ht6_inner[i].lock);
		INIT_HLIST_HEAD(&ht6_inner[i].session);
	}
	printk(KERN_INFO "xt_NAT DEBUG: nat6 htable inner mem: %u\n", sz);

	ht6_outer = kvzalloc(sz, GFP_KERNEL);
	if (!ht6_outer) {
		kvfree(ht6_inner);
		ht6_inner = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < nat6_hash_size; i++) {
		spin_lock_init(&ht6_outer[i].lock);
		INIT_HLIST_HEAD(&ht6_outer[i].session);
	}
	printk(KERN_INFO "xt_NAT DEBUG: nat6 htable outer mem: %u\n", sz);

	ht6_outer_by_addr = kvzalloc(sz, GFP_KERNEL);
	if (!ht6_outer_by_addr) {
		kvfree(ht6_outer);
		ht6_outer = NULL;
		kvfree(ht6_inner);
		ht6_inner = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < nat6_hash_size; i++) {
		spin_lock_init(&ht6_outer_by_addr[i].lock);
		INIT_HLIST_HEAD(&ht6_outer_by_addr[i].session);
	}
	printk(KERN_INFO "xt_NAT DEBUG: nat6 htable outer_by_addr mem: %u\n", sz);
	return 0;
}

static void nat6_htable_remove(void)
{
	struct nat6_htable_ent *ent;
	struct hlist_head *head;
	struct hlist_node *next;
	int i;

	if (!ht6_inner && !ht6_outer)
		return;

	if (ht6_inner && ht6_outer) {
		for (i = 0; i < nat6_hash_size; i++) {
			spin_lock_bh(&ht6_inner[i].lock);
			head = &ht6_inner[i].session;
			hlist_for_each_entry_safe(ent, next, head, list_node) {
				hlist_del_rcu(&ent->list_node);
				ht6_inner[i].use--;
				call_rcu(&ent->rcu, nat6_ent_rcu_free);
			}
			spin_unlock_bh(&ht6_inner[i].lock);
		}

		for (i = 0; i < nat6_hash_size; i++) {
			spin_lock_bh(&ht6_outer[i].lock);
			head = &ht6_outer[i].session;
			hlist_for_each_entry_safe(ent, next, head, list_node) {
				hlist_del_rcu(&ent->list_node);
				ht6_outer[i].use--;
				if (ht6_outer_by_addr) {
					unsigned int ah = get_hash_nat6_addr(ent->proto, &ent->addr);
					spin_lock_bh(&ht6_outer_by_addr[ah].lock);
					hlist_del_rcu(&ent->addr_list_node);
					ht6_outer_by_addr[ah].use--;
					spin_unlock_bh(&ht6_outer_by_addr[ah].lock);
				}
				kmem_cache_free(nat6_session_data_cachep, ent->data);
				call_rcu(&ent->rcu, nat6_ent_rcu_free);
			}
			spin_unlock_bh(&ht6_outer[i].lock);
		}
	}

	if (ht6_inner)  { kvfree(ht6_inner);  ht6_inner = NULL; }
	if (ht6_outer)  { kvfree(ht6_outer);  ht6_outer = NULL; }
	if (ht6_outer_by_addr) { kvfree(ht6_outer_by_addr); ht6_outer_by_addr = NULL; }
	printk(KERN_INFO "xt_NAT nat6_htable_remove DONE\n");
}

/* ---- session lookup ---- */

static struct nat6_htable_ent *
lookup_nat6_session(struct xt_nat_htable *ht, const uint8_t proto,
		    const struct in6_addr *addr, const uint16_t port)
{
	struct nat6_htable_ent *ent;
	struct hlist_head *head;
	unsigned int hash;

	hash = get_hash_nat6_ent(proto, addr, port);
	if (READ_ONCE(ht[hash].use) == 0)
		return NULL;

	head = &ht[hash].session;
	hlist_for_each_entry_rcu(ent, head, list_node) {
		if (likely(ent->proto == proto) && ent->port == port &&
		    time_before(jiffies, READ_ONCE(ent->data->timeout)) &&
		    ipv6_addr_equal(&ent->addr, addr))
			return ent;
	}
	return NULL;
}

static struct nat6_htable_ent *
lookup_nat6_outer_by_addr(const uint8_t proto, const struct in6_addr *addr)
{
	struct nat6_htable_ent *ent;
	struct hlist_head *head;
	unsigned int hash;

	if (unlikely(!ht6_outer_by_addr))
		return NULL;

	hash = get_hash_nat6_addr(proto, addr);
	if (READ_ONCE(ht6_outer_by_addr[hash].use) == 0)
		return NULL;

	head = &ht6_outer_by_addr[hash].session;
	hlist_for_each_entry_rcu(ent, head, addr_list_node) {
		if (ent->proto == proto &&
		    time_before(jiffies, READ_ONCE(ent->data->timeout)) &&
		    ipv6_addr_equal(&ent->addr, addr))
			return ent;
	}
	return NULL;
}

/* ---- port search (nf_nat style random probing) ---- */

#define NAT6_PORT_MIN		1024
#define NAT6_PORT_RANGE		(65535 - NAT6_PORT_MIN + 1)   /* 64512 */
#define NAT6_MAX_ATTEMPTS	128

static uint16_t search_free_l4_port6(const uint8_t proto,
				     const struct in6_addr *nataddr,
				     const uint16_t userport)
{
	unsigned int attempts = NAT6_MAX_ATTEMPTS;
	uint16_t off, i, port;

	off = get_random_u16();

another_round:
	for (i = 0; i < attempts; i++, off++) {
		port = NAT6_PORT_MIN + (off % NAT6_PORT_RANGE);
		if (!lookup_nat6_session(ht6_outer, proto, nataddr,
					 htons(port)))
			return htons(port);
	}

	if (attempts >= NAT6_PORT_RANGE || attempts < 16)
		return 0;
	attempts /= 2;
	off = get_random_u16();
	goto another_round;
}

/* ---- early drop ---- */

static uint16_t evict_nat6_session(uint8_t proto,
				   const struct in6_addr *nataddr,
				   uint16_t port_n)
{
	unsigned int hash_out = get_hash_nat6_ent(proto, nataddr, port_n);
	struct nat6_htable_ent *ent;
	struct hlist_node *tmp;
	struct nat6_htable_ent *victim = NULL;
	struct nat6_session_data *data;
	unsigned int hash_in;

	spin_lock_bh(&ht6_outer[hash_out].lock);
	hlist_for_each_entry_safe(ent, tmp, &ht6_outer[hash_out].session,
				  list_node) {
		if (ent->proto == proto && ent->port == port_n &&
		    ipv6_addr_equal(&ent->addr, nataddr)) {
			victim = ent;
			hlist_del_rcu(&ent->list_node);
			ht6_outer[hash_out].use--;
			break;
		}
	}
	spin_unlock_bh(&ht6_outer[hash_out].lock);

	if (!victim)
		return 0;

	data = victim->data;

	if (ht6_outer_by_addr) {
		unsigned int ah = get_hash_nat6_addr(proto, nataddr);
		spin_lock_bh(&ht6_outer_by_addr[ah].lock);
		hlist_del_rcu(&victim->addr_list_node);
		ht6_outer_by_addr[ah].use--;
		spin_unlock_bh(&ht6_outer_by_addr[ah].lock);
	}

	hash_in = get_hash_nat6_ent(proto, &data->in_addr, data->in_port);
	spin_lock_bh(&ht6_inner[hash_in].lock);
	hlist_for_each_entry_safe(ent, tmp, &ht6_inner[hash_in].session,
				  list_node) {
		if (ent->proto == proto && ent->data == data) {
			hlist_del_rcu(&ent->list_node);
			ht6_inner[hash_in].use--;
			call_rcu(&ent->rcu, nat6_ent_rcu_free);
			break;
		}
	}
	spin_unlock_bh(&ht6_inner[hash_in].lock);

	netflow_export_nat6(proto, &data->in_addr, data->in_port,
			    nataddr, port_n, 1);
	call_rcu(&victim->rcu, nat6_ent_rcu_free);
	kmem_cache_free(nat6_session_data_cachep, data);
	this_cpu_dec(xt_nat_stats.sessions_active);
	this_cpu_inc(xt_nat_stats.early_drops);

	return port_n;
}

static uint16_t early_drop_nat6_port(uint8_t proto,
				     const struct in6_addr *nataddr)
{
	unsigned long best_timeout = jiffies + EARLY_DROP_JIFFIES_MAX;
	uint16_t best_port_n = 0;
	int scanned = 0;
	unsigned int ah;
	struct nat6_htable_ent *ent;

	if (unlikely(!ht6_outer_by_addr))
		return 0;

	ah = get_hash_nat6_addr(proto, nataddr);
	rcu_read_lock_bh();
	hlist_for_each_entry_rcu(ent, &ht6_outer_by_addr[ah].session,
				 addr_list_node) {
		unsigned long t;

		if (scanned >= EARLY_DROP_SCAN_MAX)
			break;
		if (ent->proto == proto &&
		    ipv6_addr_equal(&ent->addr, nataddr)) {
			t = READ_ONCE(ent->data->timeout);
			if (time_before(t, best_timeout)) {
				best_timeout = t;
				best_port_n = ent->port;
			}
			scanned++;
		}
	}
	rcu_read_unlock_bh();

	if (best_port_n == 0)
		return 0;

	return evict_nat6_session(proto, nataddr, best_port_n);
}

/* ---- session creation ---- */

static struct nat6_htable_ent *
create_nat6_session(const uint8_t proto, const struct in6_addr *useraddr,
		    const uint16_t userport)
{
	struct nat6_session_data *data;
	struct nat6_htable_ent *ent_inner, *ent_outer;
	struct in6_addr nataddr;
	uint16_t natport;
	unsigned int attempt, max_attempts, hash;
	unsigned int lock_idx;

	this_cpu_inc(xt_nat_stats.sessions_tried);

	max_attempts = (nat_pool6_range_bits == 0) ? 1 : 32;

	for (attempt = 0; attempt < max_attempts; attempt++) {
		get_random_nat_addr6(&nataddr);

		rcu_read_lock_bh();
		ent_inner = lookup_nat6_session(ht6_inner, proto, useraddr,
						userport);
		if (ent_inner) {
			struct nat6_htable_ent *ret;
			ret = lookup_nat6_session(ht6_outer, proto,
						  &ent_inner->data->out_addr,
						  ent_inner->data->out_port);
			return ret;
		}

		if (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
		    proto == IPPROTO_ICMPV6) {
			natport = search_free_l4_port6(proto, &nataddr, userport);
			rcu_read_unlock_bh();
			if (natport == 0) {
				lock_idx = nat6_addr_lock_hash(&nataddr);
				spin_lock_bh(&create_session6_lock[lock_idx]);
				natport = early_drop_nat6_port(proto, &nataddr);
				if (natport == 0) {
					spin_unlock_bh(&create_session6_lock[lock_idx]);
					continue;
				}
				goto phase2_locked;
			}
		} else {
			rcu_read_unlock_bh();
			natport = userport;
		}

		lock_idx = nat6_addr_lock_hash(&nataddr);
		spin_lock_bh(&create_session6_lock[lock_idx]);

phase2_locked:
		rcu_read_lock_bh();
		ent_inner = lookup_nat6_session(ht6_inner, proto, useraddr,
						userport);
		if (unlikely(ent_inner)) {
			struct nat6_htable_ent *ret;
			ret = lookup_nat6_session(ht6_outer, proto,
						  &ent_inner->data->out_addr,
						  ent_inner->data->out_port);
			spin_unlock_bh(&create_session6_lock[lock_idx]);
			return ret;
		}

		if (lookup_nat6_session(ht6_outer, proto, &nataddr, natport)) {
			rcu_read_unlock_bh();
			spin_unlock_bh(&create_session6_lock[lock_idx]);
			continue;
		}
		rcu_read_unlock_bh();

		data = kmem_cache_zalloc(nat6_session_data_cachep, GFP_ATOMIC);
		if (!data) {
			spin_unlock_bh(&create_session6_lock[lock_idx]);
			return NULL;
		}
		ent_inner = kmem_cache_zalloc(nat6_htable_ent_cachep, GFP_ATOMIC);
		if (!ent_inner) {
			kmem_cache_free(nat6_session_data_cachep, data);
			spin_unlock_bh(&create_session6_lock[lock_idx]);
			return NULL;
		}
		ent_outer = kmem_cache_zalloc(nat6_htable_ent_cachep, GFP_ATOMIC);
		if (!ent_outer) {
			kmem_cache_free(nat6_session_data_cachep, data);
			kmem_cache_free(nat6_htable_ent_cachep, ent_inner);
			spin_unlock_bh(&create_session6_lock[lock_idx]);
			return NULL;
		}

		data->in_addr  = *useraddr;
		data->in_port  = userport;
		data->out_addr = nataddr;
		data->out_port = natport;
		WRITE_ONCE(data->timeout, jiffies + NAT_TIMEOUT_SHORT);
		data->flags = 0;

		ent_inner->proto = proto;
		ent_inner->addr  = *useraddr;
		ent_inner->port  = userport;
		ent_inner->data  = data;

		ent_outer->proto = proto;
		ent_outer->addr  = nataddr;
		ent_outer->port  = natport;
		ent_outer->data  = data;

		hash = get_hash_nat6_ent(proto, useraddr, userport);
		spin_lock_bh(&ht6_inner[hash].lock);
		hlist_add_head_rcu(&ent_inner->list_node,
				   &ht6_inner[hash].session);
		ht6_inner[hash].use++;
		spin_unlock_bh(&ht6_inner[hash].lock);

		hash = get_hash_nat6_ent(proto, &nataddr, natport);
		spin_lock_bh(&ht6_outer[hash].lock);
		hlist_add_head_rcu(&ent_outer->list_node,
				   &ht6_outer[hash].session);
		ht6_outer[hash].use++;
		spin_unlock_bh(&ht6_outer[hash].lock);

		hash = get_hash_nat6_addr(proto, &nataddr);
		spin_lock_bh(&ht6_outer_by_addr[hash].lock);
		hlist_add_head_rcu(&ent_outer->addr_list_node,
				   &ht6_outer_by_addr[hash].session);
		ht6_outer_by_addr[hash].use++;
		spin_unlock_bh(&ht6_outer_by_addr[hash].lock);

		spin_unlock_bh(&create_session6_lock[lock_idx]);

		netflow_export_nat6(proto, useraddr, userport,
				    &nataddr, natport, 0);

		if (nat_log_verbose)
			printk(KERN_INFO "xt_NAT: NAT6 assign %pI6:%u -> %pI6:%u\n",
			       useraddr, ntohs(userport),
			       &nataddr, ntohs(natport));

		this_cpu_inc(xt_nat_stats.sessions_created);
		this_cpu_inc(xt_nat_stats.sessions_active);

		rcu_read_lock_bh();
		return ent_outer;
	}
	return NULL;
}

/* ---- IPv6 data path (xtables target) ---- */

unsigned int
nat_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;
	struct icmp6hdr *icmp6 = NULL;
	struct nat6_htable_ent *session;
	struct in6_addr new_addr;
	uint16_t new_port;
	uint16_t src_port = 0, dst_port = 0;
	uint8_t l4proto;
	int l4off;
	__be16 frag_off = 0;
	const struct xt_nat_tginfo *info = par->targinfo;

	if (unlikely(skb->protocol != htons(ETH_P_IPV6))) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop not IPv6 packet\n");
		return NF_DROP;
	}
	if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr)))) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop truncated IPv6 packet\n");
		return NF_DROP;
	}

	ip6h = ipv6_hdr(skb);
	l4proto = ip6h->nexthdr;
	l4off = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &l4proto, &frag_off);
	if (unlikely(l4off < 0)) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop IPv6 packet with unsupported extension chain (nexthdr=%u, err=%d)\n",
		       (unsigned int)ip6h->nexthdr, l4off);
		return NF_DROP;
	}
	if (unlikely(frag_off)) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop fragmented IPv6 packet\n");
		return NF_DROP;
	}

	if (l4proto == IPPROTO_TCP) {
		if (unlikely(!pskb_may_pull(skb, l4off + sizeof(struct tcphdr))))
			return NF_DROP;
		if (unlikely(skb_ensure_writable(skb, l4off + sizeof(struct tcphdr))))
			return NF_DROP;
		ip6h = ipv6_hdr(skb);
		tcp = (struct tcphdr *)(skb_network_header(skb) + l4off);
		src_port = tcp->source;
		dst_port = tcp->dest;
	} else if (l4proto == IPPROTO_UDP) {
		if (unlikely(!pskb_may_pull(skb, l4off + sizeof(struct udphdr))))
			return NF_DROP;
		if (unlikely(skb_ensure_writable(skb, l4off + sizeof(struct udphdr))))
			return NF_DROP;
		ip6h = ipv6_hdr(skb);
		udp = (struct udphdr *)(skb_network_header(skb) + l4off);
		src_port = udp->source;
		dst_port = udp->dest;
	} else if (l4proto == IPPROTO_ICMPV6) {
		if (unlikely(!pskb_may_pull(skb, l4off + sizeof(struct icmp6hdr))))
			return NF_DROP;
		if (unlikely(skb_ensure_writable(skb, l4off + sizeof(struct icmp6hdr))))
			return NF_DROP;
		ip6h = ipv6_hdr(skb);
		icmp6 = (struct icmp6hdr *)(skb_network_header(skb) + l4off);
		if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST ||
		    icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
			src_port = icmp6->icmp6_identifier;
			dst_port = icmp6->icmp6_identifier;
		}
	}

	if (info->variant == XTNAT_SNAT) {
		if (ipv6_addr_type(&ip6h->saddr) & (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_MULTICAST))
			return NF_ACCEPT;
		if (in6_addr_in_pool6_range(&ip6h->saddr))
			return NF_ACCEPT;

		rcu_read_lock_bh();
		session = lookup_nat6_session(ht6_inner, l4proto,
					      &ip6h->saddr, src_port);
		if (session) {
			if (l4proto == IPPROTO_TCP && tcp) {
				if (tcp->fin || tcp->rst) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags |= FLAG_TCP_FIN;
				} else if (session->data->flags & FLAG_TCP_FIN) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags &= ~FLAG_TCP_FIN;
				} else if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
				} else {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_TCP_EST);
				}
			} else if ((session->data->flags & FLAG_REPLIED) == 0) {
				WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
			} else {
				WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_UDP_EST);
			}

			new_addr = session->data->out_addr;
			new_port = session->data->out_port;
			rcu_read_unlock_bh();
		} else {
			rcu_read_unlock_bh();
			session = create_nat6_session(l4proto, &ip6h->saddr,
						      src_port);
			if (!session) {
				printk(KERN_NOTICE "xt_NAT IPv6 SNAT: Cannot create new session. Dropping packet\n");
				return NF_DROP;
			}
			new_addr = session->data->out_addr;
			new_port = session->data->out_port;
			rcu_read_unlock_bh();
		}

		if (l4proto == IPPROTO_TCP && tcp) {
			inet_proto_csum_replace16(&tcp->check, skb,
						  (__be32 *)&ip6h->saddr,
						  (__be32 *)&new_addr, true);
			inet_proto_csum_replace2(&tcp->check, skb,
						 tcp->source, new_port, true);
			ip6h->saddr = new_addr;
			tcp->source = new_port;
		} else if (l4proto == IPPROTO_UDP && udp) {
			if (udp->check) {
				inet_proto_csum_replace16(&udp->check, skb,
							  (__be32 *)&ip6h->saddr,
							  (__be32 *)&new_addr, true);
				inet_proto_csum_replace2(&udp->check, skb,
							 udp->source, new_port, true);
			}
			ip6h->saddr = new_addr;
			udp->source = new_port;
		} else if (l4proto == IPPROTO_ICMPV6 && icmp6) {
			inet_proto_csum_replace16(&icmp6->icmp6_cksum, skb,
						  (__be32 *)&ip6h->saddr,
						  (__be32 *)&new_addr, true);
			ip6h->saddr = new_addr;
			if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST ||
			    icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
				inet_proto_csum_replace2(&icmp6->icmp6_cksum, skb,
							 icmp6->icmp6_identifier,
							 new_port, true);
				icmp6->icmp6_identifier = new_port;
			}
		} else {
			ip6h->saddr = new_addr;
		}
	} else if (info->variant == XTNAT_DNAT) {
		rcu_read_lock_bh();
		session = lookup_nat6_session(ht6_outer, l4proto,
					      &ip6h->daddr, dst_port);
		if (!session && l4proto == IPPROTO_ICMPV6 && dst_port == 0)
			session = lookup_nat6_outer_by_addr(l4proto, &ip6h->daddr);
		if (session) {
			if (l4proto == IPPROTO_TCP && tcp) {
				if (tcp->fin || tcp->rst) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags |= FLAG_TCP_FIN;
				} else if (session->data->flags & FLAG_TCP_FIN) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags &= ~FLAG_TCP_FIN;
				} else if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_TCP_EST);
					session->data->flags |= FLAG_REPLIED;
				} else {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_TCP_EST);
				}
			} else if ((session->data->flags & FLAG_REPLIED) == 0) {
				WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_UDP_EST);
				session->data->flags |= FLAG_REPLIED;
			} else {
				WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_UDP_EST);
			}

			new_addr = session->data->in_addr;
			new_port = session->data->in_port;
			rcu_read_unlock_bh();
		} else {
			rcu_read_unlock_bh();
			this_cpu_inc(xt_nat_stats.dnat_dropped);
			if (nat_log_verbose && in6_addr_in_pool6_range(&ip6h->daddr) &&
			    l4proto != IPPROTO_ICMPV6)
				printk(KERN_DEBUG "xt_NAT IPv6 DNAT: no session for proto=%u %pI6:%u\n",
				       (unsigned int)l4proto, &ip6h->daddr,
				       ntohs(dst_port));
			return NF_ACCEPT;
		}

		if (l4proto == IPPROTO_TCP && tcp) {
			inet_proto_csum_replace16(&tcp->check, skb,
						  (__be32 *)&ip6h->daddr,
						  (__be32 *)&new_addr, true);
			inet_proto_csum_replace2(&tcp->check, skb,
						 tcp->dest, new_port, true);
			ip6h->daddr = new_addr;
			tcp->dest = new_port;
		} else if (l4proto == IPPROTO_UDP && udp) {
			if (udp->check) {
				inet_proto_csum_replace16(&udp->check, skb,
							  (__be32 *)&ip6h->daddr,
							  (__be32 *)&new_addr, true);
				inet_proto_csum_replace2(&udp->check, skb,
							 udp->dest, new_port, true);
			}
			ip6h->daddr = new_addr;
			udp->dest = new_port;
		} else if (l4proto == IPPROTO_ICMPV6 && icmp6) {
			inet_proto_csum_replace16(&icmp6->icmp6_cksum, skb,
						  (__be32 *)&ip6h->daddr,
						  (__be32 *)&new_addr, true);
			ip6h->daddr = new_addr;
			if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST ||
			    icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
				inet_proto_csum_replace2(&icmp6->icmp6_cksum, skb,
							 icmp6->icmp6_identifier,
							 new_port, true);
				icmp6->icmp6_identifier = new_port;
			}
		} else {
			ip6h->daddr = new_addr;
		}
	}

	return NF_ACCEPT;
}

/* ---- GC (called from core timer) ---- */

void xt_nat_gc_ipv6(u32 start, u32 end)
{
	struct nat6_htable_ent *ent6;
	struct hlist_node *next6;
	struct hlist_head *head6;
	struct nat6_session_data *p6;
	unsigned int i;

	if (!ht6_inner || !ht6_outer)
		return;

	for (i = start; i < end; i++) {
		spin_lock_bh(&ht6_inner[i].lock);
		if (ht6_inner[i].use > 0) {
			head6 = &ht6_inner[i].session;
			hlist_for_each_entry_safe(ent6, next6, head6,
						  list_node) {
				if (time_after_eq(jiffies,
						  READ_ONCE(ent6->data->timeout))) {
					netflow_export_nat6(ent6->proto,
							    &ent6->addr,
							    ent6->port,
							    &ent6->data->out_addr,
							    ent6->data->out_port, 1);
					WRITE_ONCE(ent6->data->timeout, 0);
					hlist_del_rcu(&ent6->list_node);
					ht6_inner[i].use--;
					call_rcu(&ent6->rcu, nat6_ent_rcu_free);
				}
			}
		}
		spin_unlock_bh(&ht6_inner[i].lock);
	}

	for (i = start; i < end; i++) {
		spin_lock_bh(&ht6_outer[i].lock);
		if (ht6_outer[i].use > 0) {
			head6 = &ht6_outer[i].session;
			hlist_for_each_entry_safe(ent6, next6, head6,
						  list_node) {
				if (READ_ONCE(ent6->data->timeout) == 0) {
					hlist_del_rcu(&ent6->list_node);
					ht6_outer[i].use--;
					if (ht6_outer_by_addr) {
						unsigned int ah = get_hash_nat6_addr(
								ent6->proto, &ent6->addr);
						spin_lock_bh(&ht6_outer_by_addr[ah].lock);
						hlist_del_rcu(&ent6->addr_list_node);
						ht6_outer_by_addr[ah].use--;
						spin_unlock_bh(&ht6_outer_by_addr[ah].lock);
					}
					p6 = ent6->data;
					call_rcu(&ent6->rcu, nat6_ent_rcu_free);
					kmem_cache_free(nat6_session_data_cachep, p6);
					this_cpu_dec(xt_nat_stats.sessions_active);
				}
			}
		}
		spin_unlock_bh(&ht6_outer[i].lock);
	}
}

/* ---- init / exit ---- */

int xt_nat_ipv6_init(const char *pool6_str)
{
	int ret, i;

	ret = parse_nat_pool6(pool6_str);
	if (ret) {
		printk(KERN_INFO "xt_NAT DEBUG: BAD IPv6 Pool: %s\n", pool6_str);
		return ret;
	}
	printk(KERN_INFO "xt_NAT DEBUG: IPv6 Pool %s\n", pool6_str);

	nat6_session_data_cachep = kmem_cache_create("xt_nat6_session_data",
						     sizeof(struct nat6_session_data), 0,
						     SLAB_HWCACHE_ALIGN, NULL);
	nat6_htable_ent_cachep = kmem_cache_create("xt_nat6_htable_ent",
						   sizeof(struct nat6_htable_ent), 0,
						   SLAB_HWCACHE_ALIGN, NULL);
	if (!nat6_session_data_cachep || !nat6_htable_ent_cachep) {
		printk(KERN_ERR "xt_NAT: failed to create IPv6 slab caches\n");
		if (nat6_htable_ent_cachep)   kmem_cache_destroy(nat6_htable_ent_cachep);
		if (nat6_session_data_cachep) kmem_cache_destroy(nat6_session_data_cachep);
		return -ENOMEM;
	}

	ret = nat6_htable_create();
	if (ret)
		goto err_htable;

	for (i = 0; i < NAT6_CREATE_LOCK_SIZE; i++)
		spin_lock_init(&create_session6_lock[i]);

	return 0;

err_htable:
	kmem_cache_destroy(nat6_htable_ent_cachep);
	kmem_cache_destroy(nat6_session_data_cachep);
	return ret;
}

void xt_nat_ipv6_exit(void)
{
	nat6_htable_remove();
	kmem_cache_destroy(nat6_htable_ent_cachep);
	kmem_cache_destroy(nat6_session_data_cachep);
}
