/*
 * xt_NAT_ipv4.c - IPv4 session management, data path, and garbage collection
 *
 * Pool/htable create/remove, lookup, port search, session create/evict,
 * early drop, nat_tg() data path, per-segment GC.
 */
#include "xt_NAT_internal.h"

/* ---- globals owned by this file ---- */

u_int32_t nat_pool_start __read_mostly;
u_int32_t nat_pool_end __read_mostly;
unsigned long **port_bitmaps __read_mostly;

static struct xt_nat_htable *ht_inner __read_mostly;
static struct xt_nat_htable *ht_outer __read_mostly;
static spinlock_t *create_session_lock __read_mostly;
static struct kmem_cache *nat_session_cachep __read_mostly;
static struct kmem_cache *nat_htable_ent_cachep __read_mostly;

/* ---- helpers ---- */

static void nat_ent_rcu_free(struct rcu_head *head)
{
	kmem_cache_free(nat_htable_ent_cachep,
			container_of(head, struct nat_htable_ent, rcu));
}

static inline u_int32_t get_random_nat_addr(void)
{
	return htonl(ntohl(nat_pool_start) +
		     reciprocal_scale(get_random_u32(), get_pool_size()));
}

/* ---- hash table create / remove ---- */

static int nat_htable_create(void)
{
	unsigned int sz;
	int i;

	sz = sizeof(struct xt_nat_htable) * nat_hash_size;
	ht_inner = kzalloc(sz, GFP_KERNEL);
	if (!ht_inner)
		return -ENOMEM;
	for (i = 0; i < nat_hash_size; i++) {
		spin_lock_init(&ht_inner[i].lock);
		INIT_HLIST_HEAD(&ht_inner[i].session);
	}
	printk(KERN_INFO "xt_NAT DEBUG: sessions htable inner mem: %d\n", sz);

	ht_outer = kzalloc(sz, GFP_KERNEL);
	if (!ht_outer) {
		kfree(ht_inner);
		ht_inner = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < nat_hash_size; i++) {
		spin_lock_init(&ht_outer[i].lock);
		INIT_HLIST_HEAD(&ht_outer[i].session);
	}
	printk(KERN_INFO "xt_NAT DEBUG: sessions htable outer mem: %d\n", sz);
	return 0;
}

static void nat_htable_remove(void)
{
	struct nat_htable_ent *session;
	struct hlist_head *head;
	struct hlist_node *next;
	unsigned int i;
	struct nat_session *p;

	if (!ht_inner && !ht_outer)
		return;

	if (ht_inner) {
		for (i = 0; i < nat_hash_size; i++) {
			spin_lock_bh(&ht_inner[i].lock);
			head = &ht_inner[i].session;
			hlist_for_each_entry_safe(session, next, head, list_node) {
				hlist_del_rcu(&session->list_node);
				ht_inner[i].use--;
				call_rcu(&session->rcu, nat_ent_rcu_free);
			}
			if (ht_inner[i].use != 0)
				printk(KERN_WARNING "xt_NAT nat_htable_remove inner ERROR: bad use value: %u in element %d\n",
				       ht_inner[i].use, i);
			spin_unlock_bh(&ht_inner[i].lock);
		}
	}

	if (ht_outer) {
		for (i = 0; i < nat_hash_size; i++) {
			spin_lock_bh(&ht_outer[i].lock);
			head = &ht_outer[i].session;
			hlist_for_each_entry_safe(session, next, head, list_node) {
				hlist_del_rcu(&session->list_node);
				ht_outer[i].use--;
				p = session->data;
				call_rcu(&session->rcu, nat_ent_rcu_free);
				kmem_cache_free(nat_session_cachep, p);
			}
			if (ht_outer[i].use != 0)
				printk(KERN_WARNING "xt_NAT nat_htable_remove outer ERROR: bad use value: %u in element %d\n",
				       ht_outer[i].use, i);
			spin_unlock_bh(&ht_outer[i].lock);
		}
	}

	kfree(ht_inner);
	ht_inner = NULL;
	kfree(ht_outer);
	ht_outer = NULL;
	printk(KERN_INFO "xt_NAT nat_htable_remove DONE\n");
}

/* ---- pool / bitmap create / remove ---- */

static int pool_table_create(void)
{
	unsigned int sz, pool_size, total_bitmaps;
	int i;

	pool_size = get_pool_size();

	sz = sizeof(spinlock_t) * pool_size;
	create_session_lock = kzalloc(sz, GFP_KERNEL);
	if (!create_session_lock)
		return -ENOMEM;
	for (i = 0; i < pool_size; i++)
		spin_lock_init(&create_session_lock[i]);
	printk(KERN_INFO "xt_NAT DEBUG: nat pool table mem: %d\n", sz);

	total_bitmaps = pool_size * PORT_BITMAP_PROTOS;
	port_bitmaps = kzalloc(sizeof(unsigned long *) * total_bitmaps, GFP_KERNEL);
	if (!port_bitmaps) {
		kfree(create_session_lock);
		create_session_lock = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < total_bitmaps; i++) {
		port_bitmaps[i] = kvzalloc(BITS_TO_LONGS(PORT_BITMAP_BITS) *
					   sizeof(unsigned long), GFP_KERNEL);
		if (!port_bitmaps[i]) {
			while (i-- > 0)
				kvfree(port_bitmaps[i]);
			kfree(port_bitmaps);
			port_bitmaps = NULL;
			kfree(create_session_lock);
			create_session_lock = NULL;
			return -ENOMEM;
		}
		bitmap_set(port_bitmaps[i], 0, 1024);
	}
	printk(KERN_INFO "xt_NAT DEBUG: port bitmaps mem: %lu (%u bitmaps)\n",
	       (unsigned long)total_bitmaps * BITS_TO_LONGS(PORT_BITMAP_BITS) *
	       sizeof(unsigned long), total_bitmaps);
	return 0;
}

static void pool_table_remove(void)
{
	if (port_bitmaps) {
		unsigned int total = get_pool_size() * PORT_BITMAP_PROTOS;
		unsigned int i;
		for (i = 0; i < total; i++)
			kvfree(port_bitmaps[i]);
		kfree(port_bitmaps);
		port_bitmaps = NULL;
	}
	if (create_session_lock) {
		kfree(create_session_lock);
		create_session_lock = NULL;
	}
	printk(KERN_INFO "xt_NAT pool_table_remove DEBUG: removed\n");
}

/* ---- session lookup ---- */

static struct nat_htable_ent *
lookup_session(struct xt_nat_htable *ht, const uint8_t proto,
	       const u_int32_t addr, const uint16_t port)
{
	struct nat_htable_ent *session;
	struct hlist_head *head;
	unsigned int hash;

	hash = get_hash_nat_ent(proto, addr, port);
	if (READ_ONCE(ht[hash].use) == 0)
		return NULL;

	head = &ht[hash].session;
	hlist_for_each_entry_rcu(session, head, list_node) {
		if (likely(session->proto == proto) &&
		    session->addr == addr && session->port == port &&
		    time_before(jiffies, READ_ONCE(session->data->timeout)))
			return session;
	}
	return NULL;
}

/* ---- port search ---- */

static uint16_t search_free_l4_port(const uint8_t proto,
				    const u_int32_t nataddr,
				    const uint16_t userport)
{
	unsigned int nataddr_id = ntohl(nataddr) - ntohl(nat_pool_start);
	unsigned long *bm = get_port_bitmap(nataddr_id, proto);
	unsigned long start, port;

	if (likely(bm)) {
		start = ntohs(userport);
		if (start < 1024)
			start = 1024;
		port = find_next_zero_bit(bm, PORT_BITMAP_BITS, start);
		if (port < PORT_BITMAP_BITS)
			return htons((uint16_t)port);
		port = find_next_zero_bit(bm, start, 1024);
		if (port < start)
			return htons((uint16_t)port);
		return 0;
	}

	{
		uint16_t i, freeport;
		for (i = 0; i < 64512; i++) {
			freeport = ntohs(userport) + i;
			if (freeport < 1024)
				freeport += 1024;
			if (!lookup_session(ht_outer, proto, nataddr,
					    htons(freeport)))
				return htons(freeport);
		}
	}
	return 0;
}

/* ---- early drop ---- */

static uint16_t evict_nat_session(uint8_t proto, u_int32_t nataddr,
				  unsigned int nataddr_id, uint16_t port_h)
{
	uint16_t port_n = htons(port_h);
	unsigned int hash_out = get_hash_nat_ent(proto, nataddr, port_n);
	struct nat_htable_ent *ent, *victim = NULL;
	struct hlist_node *tmp;
	struct nat_session *data;
	unsigned int hash_in;
	unsigned long *bm;

	spin_lock_bh(&ht_outer[hash_out].lock);
	hlist_for_each_entry_safe(ent, tmp, &ht_outer[hash_out].session,
				  list_node) {
		if (ent->proto == proto && ent->addr == nataddr &&
		    ent->port == port_n) {
			victim = ent;
			hlist_del_rcu(&ent->list_node);
			ht_outer[hash_out].use--;
			break;
		}
	}
	spin_unlock_bh(&ht_outer[hash_out].lock);

	if (!victim)
		return 0;

	data = victim->data;

	hash_in = get_hash_nat_ent(proto, data->in_addr, data->in_port);
	spin_lock_bh(&ht_inner[hash_in].lock);
	hlist_for_each_entry_safe(ent, tmp, &ht_inner[hash_in].session,
				  list_node) {
		if (ent->proto == proto && ent->data == data) {
			hlist_del_rcu(&ent->list_node);
			ht_inner[hash_in].use--;
			call_rcu(&ent->rcu, nat_ent_rcu_free);
			break;
		}
	}
	spin_unlock_bh(&ht_inner[hash_in].lock);

	bm = get_port_bitmap(nataddr_id, proto);
	if (bm)
		clear_bit(port_h, bm);

	netflow_export_flow_v5(proto, data->in_addr, data->in_port,
			       nataddr, port_n, 1);
	call_rcu(&victim->rcu, nat_ent_rcu_free);
	kmem_cache_free(nat_session_cachep, data);
	this_cpu_dec(xt_nat_stats.sessions_active);
	this_cpu_inc(xt_nat_stats.early_drops);

	return port_n;
}

static uint16_t early_drop_nat_port(uint8_t proto, u_int32_t nataddr,
				    unsigned int nataddr_id)
{
	unsigned long *bm = get_port_bitmap(nataddr_id, proto);
	unsigned long scan_pos;
	int scanned;
	unsigned long best_timeout = jiffies + EARLY_DROP_JIFFIES_MAX;
	uint16_t best_port_h = 0;

	if (!bm)
		return 0;

	scan_pos = 1024 + (get_random_u32() % 64512);

	for (scanned = 0; scanned < EARLY_DROP_SCAN_MAX; scanned++) {
		struct nat_htable_ent *session;
		unsigned long t;

		scan_pos = find_next_bit(bm, PORT_BITMAP_BITS, scan_pos);
		if (scan_pos >= PORT_BITMAP_BITS) {
			scan_pos = find_next_bit(bm, PORT_BITMAP_BITS, 1024);
			if (scan_pos >= PORT_BITMAP_BITS)
				break;
		}

		rcu_read_lock_bh();
		session = lookup_session(ht_outer, proto, nataddr,
					htons((uint16_t)scan_pos));
		if (!session) {
			rcu_read_unlock_bh();
			clear_bit(scan_pos, bm);
			return htons((uint16_t)scan_pos);
		}
		t = READ_ONCE(session->data->timeout);
		rcu_read_unlock_bh();

		if (time_before(t, best_timeout)) {
			best_timeout = t;
			best_port_h = (uint16_t)scan_pos;
		}
		scan_pos++;
	}

	if (best_port_h == 0)
		return 0;

	return evict_nat_session(proto, nataddr, nataddr_id, best_port_h);
}

/* ---- session creation ---- */

static struct nat_htable_ent *
create_nat_session(const uint8_t proto, const u_int32_t useraddr,
		   const uint16_t userport)
{
	unsigned int hash;
	struct nat_htable_ent *session, *session2;
	struct nat_session *data_session;
	uint16_t natport;
	u_int32_t nataddr;
	unsigned int nataddr_id;
	unsigned int attempt, max_attempts;

	this_cpu_inc(xt_nat_stats.sessions_tried);

	max_attempts = get_pool_size();
	if (max_attempts > 32)
		max_attempts = 32;

	for (attempt = 0; attempt < max_attempts; attempt++) {
		nataddr = get_random_nat_addr();
		nataddr_id = ntohl(nataddr) - ntohl(nat_pool_start);
		spin_lock_bh(&create_session_lock[nataddr_id]);

		rcu_read_lock_bh();
		session = lookup_session(ht_inner, proto, useraddr, userport);
		if (unlikely(session)) {
			struct nat_htable_ent *ret;
			ret = lookup_session(ht_outer, proto,
					     session->data->out_addr,
					     session->data->out_port);
			spin_unlock_bh(&create_session_lock[nataddr_id]);
			return ret;
		}
		rcu_read_unlock_bh();

		if (likely(proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
			   proto == IPPROTO_ICMP)) {
			natport = search_free_l4_port(proto, nataddr, userport);
			if (natport == 0) {
				natport = early_drop_nat_port(proto, nataddr,
							     nataddr_id);
				if (natport == 0) {
					spin_unlock_bh(&create_session_lock[nataddr_id]);
					continue;
				}
			}
		} else {
			natport = userport;
		}

		data_session = kmem_cache_zalloc(nat_session_cachep, GFP_ATOMIC);
		if (unlikely(!data_session)) {
			printk(KERN_WARNING "xt_NAT create_nat_session ERROR: Cannot allocate memory for data_session\n");
			spin_unlock_bh(&create_session_lock[nataddr_id]);
			return NULL;
		}

		session = kmem_cache_zalloc(nat_htable_ent_cachep, GFP_ATOMIC);
		if (unlikely(!session)) {
			printk(KERN_WARNING "xt_NAT ERROR: Cannot allocate memory for ht_inner session\n");
			kmem_cache_free(nat_session_cachep, data_session);
			spin_unlock_bh(&create_session_lock[nataddr_id]);
			return NULL;
		}

		session2 = kmem_cache_zalloc(nat_htable_ent_cachep, GFP_ATOMIC);
		if (unlikely(!session2)) {
			printk(KERN_WARNING "xt_NAT ERROR: Cannot allocate memory for ht_outer session\n");
			kmem_cache_free(nat_session_cachep, data_session);
			kmem_cache_free(nat_htable_ent_cachep, session);
			spin_unlock_bh(&create_session_lock[nataddr_id]);
			return NULL;
		}

		data_session->in_addr = useraddr;
		data_session->in_port = userport;
		data_session->out_addr = nataddr;
		data_session->out_port = natport;
		if (nat_log_verbose)
			printk(KERN_INFO "xt_NAT: NAT assign %pI4:%u -> %pI4:%u\n",
			       &useraddr, ntohs(userport),
			       &nataddr, ntohs(natport));
		WRITE_ONCE(data_session->timeout, jiffies + NAT_TIMEOUT_EST);
		data_session->flags = 0;

		session->proto = proto;
		session->addr  = useraddr;
		session->port  = userport;
		session->data  = data_session;

		session2->proto = proto;
		session2->addr  = nataddr;
		session2->port  = natport;
		session2->data  = data_session;

		hash = get_hash_nat_ent(proto, useraddr, userport);
		spin_lock_bh(&ht_inner[hash].lock);
		hlist_add_head_rcu(&session->list_node,
				   &ht_inner[hash].session);
		ht_inner[hash].use++;
		spin_unlock_bh(&ht_inner[hash].lock);

		hash = get_hash_nat_ent(proto, nataddr, natport);
		spin_lock_bh(&ht_outer[hash].lock);
		hlist_add_head_rcu(&session2->list_node,
				   &ht_outer[hash].session);
		ht_outer[hash].use++;
		spin_unlock_bh(&ht_outer[hash].lock);

		{
			unsigned long *bm = get_port_bitmap(nataddr_id, proto);
			if (bm)
				set_bit(ntohs(natport), bm);
		}

		spin_unlock_bh(&create_session_lock[nataddr_id]);

		netflow_export_flow_v5(proto, useraddr, userport,
				       nataddr, natport, 0);

		this_cpu_inc(xt_nat_stats.sessions_created);
		this_cpu_inc(xt_nat_stats.sessions_active);

		rcu_read_lock_bh();
		return session2;
	}

	printk(KERN_WARNING "xt_NAT create_nat_session ERROR: Not found free nat port for %d %pI4:%u in NAT pool\n",
	       proto, &useraddr, userport);
	return NULL;
}

/* ---- IPv4 data path (xtables target) ---- */

unsigned int
nat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;
	struct nat_htable_ent *session;
	uint16_t nat_port;
	const struct xt_nat_tginfo *info = par->targinfo;

	if (unlikely(skb->protocol != htons(ETH_P_IP))) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop not IP packet\n");
		return NF_DROP;
	}
	if (unlikely(ip_hdrlen(skb) != sizeof(struct iphdr))) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop truncated IP packet\n");
		return NF_DROP;
	}

	ip = (struct iphdr *)skb_network_header(skb);

	if (unlikely(ip->frag_off & htons(IP_OFFSET))) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop fragmented IP packet\n");
		return NF_DROP;
	}
	if (unlikely(ip->version != 4)) {
		printk(KERN_DEBUG "xt_NAT DEBUG: Drop not IPv4 IP packet\n");
		return NF_DROP;
	}

	if (info->variant == XTNAT_SNAT) {
		if (ip->protocol == IPPROTO_TCP) {
			if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
				printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated TCP packet\n");
				return NF_DROP;
			}
			if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr))))
				return NF_DROP;
			ip = ip_hdr(skb);
			tcp = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

			rcu_read_lock_bh();
			session = lookup_session(ht_inner, ip->protocol, ip->saddr, tcp->source);
			if (session) {
				csum_replace4(&ip->check, ip->saddr, session->data->out_addr);
				inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->data->out_addr, true);
				inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->data->out_port, true);
				ip->saddr = session->data->out_addr;
				tcp->source = session->data->out_port;

				if (tcp->fin || tcp->rst) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags |= FLAG_TCP_FIN;
				} else if (session->data->flags & FLAG_TCP_FIN) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags &= ~FLAG_TCP_FIN;
				} else if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
				} else {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_EST);
				}
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				session = create_nat_session(ip->protocol, ip->saddr, tcp->source);
				if (!session) {
					printk(KERN_NOTICE "xt_NAT SNAT: Cannot create new session. Dropping packet\n");
					return NF_DROP;
				}
				csum_replace4(&ip->check, ip->saddr, session->addr);
				inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->addr, true);
				inet_proto_csum_replace2(&tcp->check, skb, session->data->in_port, session->data->out_port, true);
				ip->saddr = session->addr;
				tcp->source = session->data->out_port;
				rcu_read_unlock_bh();
			}
		} else if (ip->protocol == IPPROTO_UDP) {
			if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
				printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated UDP packet\n");
				return NF_DROP;
			}
			if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct udphdr))))
				return NF_DROP;
			ip = ip_hdr(skb);
			udp = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

			rcu_read_lock_bh();
			session = lookup_session(ht_inner, ip->protocol, ip->saddr, udp->source);
			if (session) {
				csum_replace4(&ip->check, ip->saddr, session->data->out_addr);
				if (udp->check) {
					inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->data->out_addr, true);
					inet_proto_csum_replace2(&udp->check, skb, udp->source, session->data->out_port, true);
				}
				ip->saddr = session->data->out_addr;
				udp->source = session->data->out_port;

				if ((session->data->flags & FLAG_REPLIED) == 0)
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
				else
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_EST);
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				session = create_nat_session(ip->protocol, ip->saddr, udp->source);
				if (!session) {
					printk(KERN_NOTICE "xt_NAT SNAT: Cannot create new session. Dropping packet\n");
					return NF_DROP;
				}
				csum_replace4(&ip->check, ip->saddr, session->addr);
				if (udp->check) {
					inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->addr, true);
					inet_proto_csum_replace2(&udp->check, skb, session->data->in_port, session->data->out_port, true);
				}
				ip->saddr = session->addr;
				udp->source = session->data->out_port;
				rcu_read_unlock_bh();
			}
		} else if (ip->protocol == IPPROTO_ICMP) {
			if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
				printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated ICMP packet\n");
				return NF_DROP;
			}
			if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr))))
				return NF_DROP;
			ip = ip_hdr(skb);
			icmp = (struct icmphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

			nat_port = 0;
			if (icmp->type == 0 || icmp->type == 8)
				nat_port = icmp->un.echo.id;

			rcu_read_lock_bh();
			session = lookup_session(ht_inner, ip->protocol, ip->saddr, nat_port);
			if (session) {
				csum_replace4(&ip->check, ip->saddr, session->data->out_addr);
				ip->saddr = session->data->out_addr;
				if (icmp->type == 0 || icmp->type == 8) {
					inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->out_port, true);
					icmp->un.echo.id = session->data->out_port;
				}
				if ((session->data->flags & FLAG_REPLIED) == 0)
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
				else
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				session = create_nat_session(ip->protocol, ip->saddr, nat_port);
				if (!session) {
					printk(KERN_NOTICE "xt_NAT SNAT: Cannot create new session. Dropping packet\n");
					return NF_DROP;
				}
				csum_replace4(&ip->check, ip->saddr, session->addr);
				ip->saddr = session->addr;
				if (icmp->type == 0 || icmp->type == 8) {
					inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->out_port, true);
					icmp->un.echo.id = session->data->out_port;
				}
				rcu_read_unlock_bh();
			}
		} else {
			rcu_read_lock_bh();
			session = lookup_session(ht_inner, ip->protocol, ip->saddr, 0);
			if (session) {
				csum_replace4(&ip->check, ip->saddr, session->data->out_addr);
				ip->saddr = session->data->out_addr;
				if ((session->data->flags & FLAG_REPLIED) == 0)
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
				else
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_EST);
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				session = create_nat_session(ip->protocol, ip->saddr, 0);
				if (!session) {
					printk(KERN_NOTICE "xt_NAT SNAT: Cannot create new session. Dropping packet\n");
					return NF_DROP;
				}
				csum_replace4(&ip->check, ip->saddr, session->addr);
				ip->saddr = session->addr;
				rcu_read_unlock_bh();
			}
		}
	} else if (info->variant == XTNAT_DNAT) {
		if (ip->protocol == IPPROTO_TCP) {
			if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
				printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated TCP packet\n");
				return NF_DROP;
			}
			if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr))))
				return NF_DROP;
			ip = ip_hdr(skb);
			tcp = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

			rcu_read_lock_bh();
			session = lookup_session(ht_outer, ip->protocol, ip->daddr, tcp->dest);
			if (likely(session)) {
				csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
				inet_proto_csum_replace4(&tcp->check, skb, ip->daddr, session->data->in_addr, true);
				inet_proto_csum_replace2(&tcp->check, skb, tcp->dest, session->data->in_port, true);
				ip->daddr = session->data->in_addr;
				tcp->dest = session->data->in_port;

				if (tcp->fin || tcp->rst) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags |= FLAG_TCP_FIN;
				} else if (session->data->flags & FLAG_TCP_FIN) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_CLOSE);
					session->data->flags &= ~FLAG_TCP_FIN;
				} else if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_EST);
					session->data->flags |= FLAG_REPLIED;
				}
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				this_cpu_inc(xt_nat_stats.dnat_dropped);
			}
		} else if (ip->protocol == IPPROTO_UDP) {
			if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
				printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated UDP packet\n");
				return NF_DROP;
			}
			if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct udphdr))))
				return NF_DROP;
			ip = ip_hdr(skb);
			udp = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

			rcu_read_lock_bh();
			session = lookup_session(ht_outer, ip->protocol, ip->daddr, udp->dest);
			if (likely(session)) {
				csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
				if (udp->check) {
					inet_proto_csum_replace4(&udp->check, skb, ip->daddr, session->data->in_addr, true);
					inet_proto_csum_replace2(&udp->check, skb, udp->dest, session->data->in_port, true);
				}
				ip->daddr = session->data->in_addr;
				udp->dest = session->data->in_port;

				if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_EST);
					session->data->flags |= FLAG_REPLIED;
				}
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				this_cpu_inc(xt_nat_stats.dnat_dropped);
			}
		} else if (ip->protocol == IPPROTO_ICMP) {
			if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
				printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated ICMP packet\n");
				return NF_DROP;
			}
			if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr))))
				return NF_DROP;
			ip = ip_hdr(skb);
			icmp = (struct icmphdr *)(skb_network_header(skb) + ip_hdrlen(skb));

			nat_port = 0;
			if (icmp->type == 0 || icmp->type == 8) {
				nat_port = icmp->un.echo.id;
			} else if (icmp->type == 3 || icmp->type == 4 || icmp->type == 5 ||
				   icmp->type == 11 || icmp->type == 12 || icmp->type == 31) {
				struct iphdr *inner_ip;
				unsigned int inner_l4off;

				this_cpu_inc(xt_nat_stats.related_icmp);
				if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) +
				    sizeof(struct iphdr) + 8) {
					printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet with truncated inner header\n");
					return NF_DROP;
				}
				if (unlikely(skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr) +
								  sizeof(struct iphdr) + 8)))
					return NF_DROP;
				ip = ip_hdr(skb);
				icmp = (struct icmphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
				inner_ip = (struct iphdr *)((char *)icmp + sizeof(struct icmphdr));
				inner_l4off = ip_hdrlen(skb) + sizeof(struct icmphdr) + (inner_ip->ihl * 4);

				if (inner_ip->protocol == IPPROTO_TCP) {
					tcp = (struct tcphdr *)(skb_network_header(skb) + inner_l4off);
					rcu_read_lock_bh();
					session = lookup_session(ht_outer, inner_ip->protocol, inner_ip->saddr, tcp->source);
					if (session) {
						csum_replace4(&inner_ip->check, inner_ip->saddr, session->data->in_addr);
						inner_ip->saddr = session->data->in_addr;
						tcp->source = session->data->in_port;
						csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
						ip->daddr = session->data->in_addr;
					}
					rcu_read_unlock_bh();
				} else if (inner_ip->protocol == IPPROTO_UDP) {
					udp = (struct udphdr *)(skb_network_header(skb) + inner_l4off);
					rcu_read_lock_bh();
					session = lookup_session(ht_outer, inner_ip->protocol, inner_ip->saddr, udp->source);
					if (session) {
						csum_replace4(&inner_ip->check, inner_ip->saddr, session->data->in_addr);
						inner_ip->saddr = session->data->in_addr;
						udp->source = session->data->in_port;
						csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
						ip->daddr = session->data->in_addr;
					}
					rcu_read_unlock_bh();
				} else if (inner_ip->protocol == IPPROTO_ICMP) {
					struct icmphdr *inner_icmp = (struct icmphdr *)(skb_network_header(skb) + inner_l4off);
					nat_port = 0;
					if (inner_icmp->type == 0 || inner_icmp->type == 8)
						nat_port = inner_icmp->un.echo.id;
					rcu_read_lock_bh();
					session = lookup_session(ht_outer, inner_ip->protocol, inner_ip->saddr, nat_port);
					if (session) {
						csum_replace4(&inner_ip->check, inner_ip->saddr, session->data->in_addr);
						inner_ip->saddr = session->data->in_addr;
						if (inner_icmp->type == 0 || inner_icmp->type == 8) {
							inet_proto_csum_replace2(&inner_icmp->checksum, skb, nat_port, session->data->in_port, true);
							inner_icmp->un.echo.id = session->data->in_port;
						}
						csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
						ip->daddr = session->data->in_addr;
					}
					rcu_read_unlock_bh();
				}
				return NF_ACCEPT;
			}

			rcu_read_lock_bh();
			session = lookup_session(ht_outer, ip->protocol, ip->daddr, nat_port);
			if (likely(session)) {
				csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
				ip->daddr = session->data->in_addr;
				if (icmp->type == 0 || icmp->type == 8) {
					inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->in_port, true);
					icmp->un.echo.id = session->data->in_port;
				}
				if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_SHORT);
					session->data->flags |= FLAG_REPLIED;
				}
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				this_cpu_inc(xt_nat_stats.dnat_dropped);
			}
		} else {
			nat_port = 0;
			rcu_read_lock_bh();
			session = lookup_session(ht_outer, ip->protocol, ip->daddr, nat_port);
			if (likely(session)) {
				csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
				ip->daddr = session->data->in_addr;
				if ((session->data->flags & FLAG_REPLIED) == 0) {
					WRITE_ONCE(session->data->timeout, jiffies + NAT_TIMEOUT_EST);
					session->data->flags |= FLAG_REPLIED;
				}
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				this_cpu_inc(xt_nat_stats.dnat_dropped);
			}
		}
	}

	return NF_ACCEPT;
}

/* ---- GC (called from core timer) ---- */

void xt_nat_gc_ipv4(u32 start, u32 end)
{
	struct nat_htable_ent *session;
	struct hlist_head *head;
	struct hlist_node *next;
	struct nat_session *p;
	unsigned int i;

	if (!ht_inner || !ht_outer)
		return;

	for (i = start; i < end; i++) {
		spin_lock_bh(&ht_inner[i].lock);
		if (ht_inner[i].use > 0) {
			head = &ht_inner[i].session;
			hlist_for_each_entry_safe(session, next, head,
						  list_node) {
				if (time_after_eq(jiffies,
						  READ_ONCE(session->data->timeout))) {
					netflow_export_flow_v5(session->proto,
							       session->addr,
							       session->port,
							       session->data->out_addr,
							       session->data->out_port, 1);
					WRITE_ONCE(session->data->timeout, 0);
					hlist_del_rcu(&session->list_node);
					ht_inner[i].use--;
					call_rcu(&session->rcu, nat_ent_rcu_free);
				}
			}
		}
		spin_unlock_bh(&ht_inner[i].lock);
	}

	for (i = start; i < end; i++) {
		spin_lock_bh(&ht_outer[i].lock);
		if (ht_outer[i].use > 0) {
			head = &ht_outer[i].session;
			hlist_for_each_entry_safe(session, next, head,
						  list_node) {
				if (READ_ONCE(session->data->timeout) == 0) {
					hlist_del_rcu(&session->list_node);
					ht_outer[i].use--;
					{
						unsigned int aid = ntohl(session->addr) -
								   ntohl(nat_pool_start);
						unsigned long *bm = get_port_bitmap(aid,
										    session->proto);
						if (bm)
							clear_bit(ntohs(session->port), bm);
					}
					p = session->data;
					call_rcu(&session->rcu, nat_ent_rcu_free);
					kmem_cache_free(nat_session_cachep, p);
					this_cpu_dec(xt_nat_stats.sessions_active);
				}
			}
		}
		spin_unlock_bh(&ht_outer[i].lock);
	}
}

/* ---- init / exit ---- */

int xt_nat_ipv4_init(const char *pool_str)
{
	char buff[128] = { 0 };
	int i, j, ret;

	for (i = 0, j = 0; i < 128 && pool_str[i] != '-' && pool_str[i] != '\0'; i++, j++)
		buff[j] = pool_str[i];
	nat_pool_start = in_aton(buff);

	memset(buff, 0, sizeof(buff));
	for (i++, j = 0; i < 128 && pool_str[i] != '-' && pool_str[i] != '\0'; i++, j++)
		buff[j] = pool_str[i];
	nat_pool_end = in_aton(buff);

	if (!nat_pool_start || !nat_pool_end || nat_pool_start > nat_pool_end) {
		printk(KERN_INFO "xt_NAT DEBUG: BAD IP Pool from %pI4 to %pI4\n",
		       &nat_pool_start, &nat_pool_end);
		return -EINVAL;
	}
	printk(KERN_INFO "xt_NAT DEBUG: IP Pool from %pI4 to %pI4\n",
	       &nat_pool_start, &nat_pool_end);

	nat_session_cachep = kmem_cache_create("xt_nat_session",
					       sizeof(struct nat_session), 0,
					       SLAB_HWCACHE_ALIGN, NULL);
	nat_htable_ent_cachep = kmem_cache_create("xt_nat_htable_ent",
						  sizeof(struct nat_htable_ent), 0,
						  SLAB_HWCACHE_ALIGN, NULL);
	if (!nat_session_cachep || !nat_htable_ent_cachep) {
		printk(KERN_ERR "xt_NAT: failed to create IPv4 slab caches\n");
		if (nat_htable_ent_cachep) kmem_cache_destroy(nat_htable_ent_cachep);
		if (nat_session_cachep)    kmem_cache_destroy(nat_session_cachep);
		return -ENOMEM;
	}

	ret = nat_htable_create();
	if (ret)
		goto err_htable;

	ret = pool_table_create();
	if (ret)
		goto err_pool;

	return 0;

err_pool:
	nat_htable_remove();
err_htable:
	kmem_cache_destroy(nat_htable_ent_cachep);
	kmem_cache_destroy(nat_session_cachep);
	return ret;
}

void xt_nat_ipv4_exit(void)
{
	pool_table_remove();
	nat_htable_remove();
	kmem_cache_destroy(nat_htable_ent_cachep);
	kmem_cache_destroy(nat_session_cachep);
}
