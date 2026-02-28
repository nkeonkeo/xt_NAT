/*
 * xt_NAT_netflow.c - Netflow v9 (RFC 3954) export subsystem
 *
 * Socket management, template-based PDU assembly, IPv4+IPv6 dual buffer,
 * and periodic flush for Netflow v9 records.
 */
#include "xt_NAT_internal.h"

/* ---- socket management (unchanged) ---- */

static LIST_HEAD(usock_list);
static int sndbuf = 1310720;

static DEFINE_SPINLOCK(nfsend_lock);
static struct timer_list nf_send_timer;

/* ---- v9 state ---- */

static int engine_id;
static unsigned int nf9_seq;
static unsigned int nf9_pkt_count;

static struct nf9_nat4_record nf9_v4_buf[NF9_V4_MAX];
static unsigned int nf9_v4_count;

static struct nf9_nat6_record nf9_v6_buf[NF9_V6_MAX];
static unsigned int nf9_v6_count;

/* pre-built template FlowSets (assembled once at init) */

struct nf9_tmpl4_flowset {
	struct nf9_flowset_header hdr;
	__be16 template_id;
	__be16 field_count;
	struct nf9_template_field fields[NF9_NAT4_FIELD_COUNT];
} __attribute__((packed));

struct nf9_tmpl6_flowset {
	struct nf9_flowset_header hdr;
	__be16 template_id;
	__be16 field_count;
	struct nf9_template_field fields[NF9_NAT6_FIELD_COUNT];
} __attribute__((packed));

static struct nf9_tmpl4_flowset tmpl4_fs;
static struct nf9_tmpl6_flowset tmpl6_fs;

static void build_templates(void)
{
	/* IPv4 NAT template (ID 256) */
	tmpl4_fs.hdr.flowset_id = htons(NF9_FLOWSET_TEMPLATE);
	tmpl4_fs.hdr.length     = htons(sizeof(tmpl4_fs));
	tmpl4_fs.template_id    = htons(NF9_TMPL_ID_NAT4);
	tmpl4_fs.field_count    = htons(NF9_NAT4_FIELD_COUNT);

	tmpl4_fs.fields[0] = (struct nf9_template_field){ htons(NF9_IPV4_SRC_ADDR),  htons(4) };
	tmpl4_fs.fields[1] = (struct nf9_template_field){ htons(NF9_L4_SRC_PORT),    htons(2) };
	tmpl4_fs.fields[2] = (struct nf9_template_field){ htons(NF9_IPV4_DST_ADDR),  htons(4) };
	tmpl4_fs.fields[3] = (struct nf9_template_field){ htons(NF9_L4_DST_PORT),    htons(2) };
	tmpl4_fs.fields[4] = (struct nf9_template_field){ htons(NF9_PROTOCOL),        htons(1) };
	tmpl4_fs.fields[5] = (struct nf9_template_field){ htons(NF9_TCP_FLAGS),       htons(1) };
	tmpl4_fs.fields[6] = (struct nf9_template_field){ htons(NF9_FIRST_SWITCHED),  htons(4) };
	tmpl4_fs.fields[7] = (struct nf9_template_field){ htons(NF9_LAST_SWITCHED),   htons(4) };

	/* IPv6 NAT template (ID 257) */
	tmpl6_fs.hdr.flowset_id = htons(NF9_FLOWSET_TEMPLATE);
	tmpl6_fs.hdr.length     = htons(sizeof(tmpl6_fs));
	tmpl6_fs.template_id    = htons(NF9_TMPL_ID_NAT6);
	tmpl6_fs.field_count    = htons(NF9_NAT6_FIELD_COUNT);

	tmpl6_fs.fields[0] = (struct nf9_template_field){ htons(NF9_IPV6_SRC_ADDR),  htons(16) };
	tmpl6_fs.fields[1] = (struct nf9_template_field){ htons(NF9_L4_SRC_PORT),    htons(2) };
	tmpl6_fs.fields[2] = (struct nf9_template_field){ htons(NF9_IPV6_DST_ADDR),  htons(16) };
	tmpl6_fs.fields[3] = (struct nf9_template_field){ htons(NF9_L4_DST_PORT),    htons(2) };
	tmpl6_fs.fields[4] = (struct nf9_template_field){ htons(NF9_PROTOCOL),        htons(1) };
	tmpl6_fs.fields[5] = (struct nf9_template_field){ htons(NF9_TCP_FLAGS),       htons(1) };
	tmpl6_fs.fields[6] = (struct nf9_template_field){ htons(NF9_FIRST_SWITCHED),  htons(4) };
	tmpl6_fs.fields[7] = (struct nf9_template_field){ htons(NF9_LAST_SWITCHED),   htons(4) };
}

/* ---- socket helpers ---- */

static char *print_sockaddr(const struct sockaddr_storage *ss)
{
	static char buf[64];
	snprintf(buf, sizeof(buf), "%pISpc", ss);
	return buf;
}

static void nat_sk_error_report(struct sock *sk)
{
	sk->sk_err = 0;
}

static struct socket *usock_open_sock(const struct sockaddr_storage *addr,
				      void *user_data)
{
	struct socket *sock;
	int error;

	error = sock_create_kern(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP,
				 &sock);
	if (error < 0) {
		printk(KERN_WARNING "xt_NAT NEL: sock_create_kern error %d\n",
		       -error);
		return NULL;
	}
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_prot->unhash(sock->sk);
	sock->sk->sk_error_report = &nat_sk_error_report;
	sock->sk->sk_user_data = user_data;

	if (sndbuf < SOCK_MIN_SNDBUF)
		sndbuf = SOCK_MIN_SNDBUF;
	if (sndbuf)
		sock->sk->sk_sndbuf = sndbuf;
	else
		sndbuf = sock->sk->sk_sndbuf;

	error = sock->ops->connect(sock, (struct sockaddr *)addr,
				   sizeof(*addr), 0);
	if (error < 0) {
		printk(KERN_WARNING "xt_NAT NEL: error connecting UDP socket %d,"
		       " don't worry, will try reconnect later.\n", -error);
		return NULL;
	}
	return sock;
}

static void netflow_sendmsg(void *buffer, const int len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec iov = { buffer, len };
	struct netflow_sock *usock;
	int ret;

	list_for_each_entry(usock, &usock_list, list) {
		if (!usock->sock)
			usock->sock = usock_open_sock(&usock->addr, usock);
		if (!usock->sock)
			continue;
		ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
		if (ret == -EINVAL)
			usock->sock = NULL;
		else if (ret == -EAGAIN)
			printk(KERN_WARNING "xt_NAT NEL: increase sndbuf!\n");
	}
}

/* ---- v9 packet assembly & flush ---- */

#define NF9_BUF_SIZE 1500

static void nf9_flush(void)
{
	u8 buf[NF9_BUF_SIZE];
	struct nf9_header *hdr;
	struct nf9_flowset_header *dfs;
	struct timespec64 ts;
	unsigned int offset = 0;
	unsigned int flowset_count = 0;
	unsigned int data_len, pad_len;
	bool send_templates;

	if (!nf9_v4_count && !nf9_v6_count)
		return;

	send_templates = (nf9_pkt_count % NF9_TMPL_INTERVAL == 0);

	/* reserve space for packet header */
	offset = sizeof(struct nf9_header);

	/* template FlowSets (periodic) */
	if (send_templates) {
		memcpy(buf + offset, &tmpl4_fs, sizeof(tmpl4_fs));
		offset += sizeof(tmpl4_fs);
		flowset_count++;

		memcpy(buf + offset, &tmpl6_fs, sizeof(tmpl6_fs));
		offset += sizeof(tmpl6_fs);
		flowset_count++;
	}

	/* IPv4 data FlowSet */
	if (nf9_v4_count > 0) {
		data_len = nf9_v4_count * sizeof(struct nf9_nat4_record);
		pad_len = (4 - ((sizeof(struct nf9_flowset_header) + data_len) % 4)) % 4;

		dfs = (struct nf9_flowset_header *)(buf + offset);
		dfs->flowset_id = htons(NF9_TMPL_ID_NAT4);
		dfs->length = htons(sizeof(struct nf9_flowset_header) + data_len + pad_len);
		offset += sizeof(struct nf9_flowset_header);

		memcpy(buf + offset, nf9_v4_buf, data_len);
		offset += data_len;

		if (pad_len) {
			memset(buf + offset, 0, pad_len);
			offset += pad_len;
		}
		flowset_count++;
	}

	/* IPv6 data FlowSet */
	if (nf9_v6_count > 0) {
		data_len = nf9_v6_count * sizeof(struct nf9_nat6_record);
		pad_len = (4 - ((sizeof(struct nf9_flowset_header) + data_len) % 4)) % 4;

		dfs = (struct nf9_flowset_header *)(buf + offset);
		dfs->flowset_id = htons(NF9_TMPL_ID_NAT6);
		dfs->length = htons(sizeof(struct nf9_flowset_header) + data_len + pad_len);
		offset += sizeof(struct nf9_flowset_header);

		memcpy(buf + offset, nf9_v6_buf, data_len);
		offset += data_len;

		if (pad_len) {
			memset(buf + offset, 0, pad_len);
			offset += pad_len;
		}
		flowset_count++;
	}

	/* fill packet header */
	hdr = (struct nf9_header *)buf;
	hdr->version   = htons(NF9_VERSION);
	hdr->count     = htons(flowset_count);
	hdr->sys_uptime = htonl(jiffies_to_msecs(jiffies));
	ktime_get_real_ts64(&ts);
	hdr->unix_secs = htonl((u32)ts.tv_sec);
	hdr->sequence  = htonl(nf9_seq);
	hdr->source_id = htonl(engine_id);

	netflow_sendmsg(buf, offset);

	nf9_seq++;
	nf9_pkt_count++;
	nf9_v4_count = 0;
	nf9_v6_count = 0;
}

/*
 * spin_trylock: if lock is held (timer flush or another CPU exporting),
 * drop this record rather than blocking — Netflow is best-effort.
 */
void netflow_export_nat4(const uint8_t proto, const u_int32_t useraddr,
			 const uint16_t userport, const u_int32_t nataddr,
			 const uint16_t natport, const int event)
{
	struct nf9_nat4_record *rec;
	__be32 uptime_ms;

	if (!spin_trylock_bh(&nfsend_lock))
		return;

	uptime_ms = htonl(jiffies_to_msecs(jiffies));

	rec = &nf9_v4_buf[nf9_v4_count++];
	rec->src_addr       = useraddr;
	rec->src_port       = userport;
	rec->dst_addr       = nataddr;
	rec->dst_port       = natport;
	rec->protocol       = proto;
	rec->tcp_flags      = (event == 0) ? TCP_SYN_ACK : TCP_FIN_RST;
	rec->first_switched = uptime_ms;
	rec->last_switched  = uptime_ms;

	if (nf9_v4_count == NF9_V4_MAX)
		nf9_flush();

	spin_unlock_bh(&nfsend_lock);
}

void netflow_export_nat6(const uint8_t proto,
			 const struct in6_addr *useraddr,
			 const uint16_t userport,
			 const struct in6_addr *nataddr,
			 const uint16_t natport, const int event)
{
	struct nf9_nat6_record *rec;
	__be32 uptime_ms;

	if (!spin_trylock_bh(&nfsend_lock))
		return;

	uptime_ms = htonl(jiffies_to_msecs(jiffies));

	rec = &nf9_v6_buf[nf9_v6_count++];
	memcpy(rec->src_addr, useraddr->s6_addr, 16);
	rec->src_port       = userport;
	memcpy(rec->dst_addr, nataddr->s6_addr, 16);
	rec->dst_port       = natport;
	rec->protocol       = proto;
	rec->tcp_flags      = (event == 0) ? TCP_SYN_ACK : TCP_FIN_RST;
	rec->first_switched = uptime_ms;
	rec->last_switched  = uptime_ms;

	if (nf9_v6_count == NF9_V6_MAX)
		nf9_flush();

	spin_unlock_bh(&nfsend_lock);
}

/* ---- timer ---- */

static void nf_send_timer_callback(struct timer_list *timer)
{
	(void)timer;
	if (READ_ONCE(nat_exiting))
		return;
	spin_lock_bh(&nfsend_lock);
	nf9_flush();
	mod_timer(&nf_send_timer, jiffies + msecs_to_jiffies(1000));
	spin_unlock_bh(&nfsend_lock);
}

/* ---- destination parsing ---- */

#define SEPARATORS " ,;\t\n"
static int add_nf_destinations(const char *ptr)
{
	int len;

	for (; ptr; ptr += len) {
		struct sockaddr_storage ss;
		struct netflow_sock *usock;
		struct sockaddr_in *sin;
		const char *end;
		int succ = 0;

		ptr += strspn(ptr, SEPARATORS);
		len = strcspn(ptr, SEPARATORS);
		if (!len)
			break;

		memset(&ss, 0, sizeof(ss));
		sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(2055);
		succ = in4_pton(ptr, len, (u8 *)&sin->sin_addr, -1, &end);
		if (succ && *end == ':')
			sin->sin_port = htons(simple_strtoul(++end, NULL, 0));

		if (!succ) {
			printk(KERN_ERR "xt_NAT: can't parse netflow destination: %.*s\n",
			       len, ptr);
			continue;
		}

		usock = vmalloc(sizeof(*usock));
		if (!usock) {
			printk(KERN_ERR "xt_NAT: can't vmalloc socket\n");
			return -ENOMEM;
		}
		memset(usock, 0, sizeof(*usock));
		usock->addr = ss;
		list_add_tail(&usock->list, &usock_list);
		printk(KERN_INFO "xt_NAT NEL: add destination %s\n",
		       print_sockaddr(&usock->addr));
	}
	return 0;
}

/* ---- init / exit ---- */

int xt_nat_netflow_init(const char *dest)
{
	build_templates();
	add_nf_destinations(dest);

	spin_lock_bh(&nfsend_lock);
	timer_setup(&nf_send_timer, nf_send_timer_callback, 0);
	mod_timer(&nf_send_timer, jiffies + msecs_to_jiffies(1000));
	spin_unlock_bh(&nfsend_lock);

	return 0;
}

void xt_nat_netflow_exit(void)
{
	del_timer_sync(&nf_send_timer);

	spin_lock_bh(&nfsend_lock);
	nf9_flush();
	spin_unlock_bh(&nfsend_lock);

	while (!list_empty(&usock_list)) {
		struct netflow_sock *usock;

		usock = list_entry(usock_list.next, struct netflow_sock, list);
		list_del(&usock->list);
		if (usock->sock)
			sock_release(usock->sock);
		usock->sock = NULL;
		vfree(usock);
	}
}
