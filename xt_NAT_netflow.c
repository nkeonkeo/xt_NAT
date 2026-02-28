/*
 * xt_NAT_netflow.c - Netflow v5 export subsystem
 *
 * Socket management, PDU assembly, and periodic flush for Netflow v5 records.
 */
#include "xt_NAT_internal.h"

static LIST_HEAD(usock_list);
static int sndbuf = 1310720;
static int engine_id;
static unsigned int pdu_data_records;
static unsigned int pdu_seq;
static struct netflow5_pdu pdu;

static DEFINE_SPINLOCK(nfsend_lock);
static struct timer_list nf_send_timer;

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

static void netflow_export_pdu_v5(void)
{
	struct timespec64 ts;
	int pdusize;

	if (!pdu_data_records)
		return;

	pdu.version	= htons(5);
	pdu.nr_records	= htons(pdu_data_records);
	pdu.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
	ktime_get_real_ts64(&ts);
	pdu.ts_usecs	= htonl((u32)ts.tv_sec);
	pdu.ts_unsecs	= htonl((u32)(ts.tv_nsec / 1000));
	pdu.seq		= htonl(pdu_seq);
	pdu.eng_id	= (__u8)engine_id;

	pdusize = NETFLOW5_HEADER_SIZE +
		  sizeof(struct netflow5_record) * pdu_data_records;
	netflow_sendmsg(&pdu, pdusize);

	pdu_seq += pdu_data_records;
	pdu_data_records = 0;
}

/*
 * 使用 spin_trylock 减少数据面路径上的 nfsend_lock 争用。
 * 若锁被占用（定时器 flush 或另一 CPU 在导出），丢弃本条记录而非阻塞——
 * Netflow 本身是"尽力而为"的统计导出协议，允许丢失。
 */
void netflow_export_flow_v5(const uint8_t proto, const u_int32_t useraddr,
			    const uint16_t userport, const u_int32_t nataddr,
			    const uint16_t natport, const int flags)
{
	struct netflow5_record *rec;

	if (!spin_trylock_bh(&nfsend_lock))
		return;

	rec = &pdu.flow[pdu_data_records++];

	rec->s_addr	= useraddr;
	rec->d_addr	= nataddr;
	rec->nexthop	= nataddr;
	rec->i_ifc	= 0;
	rec->o_ifc	= 0;
	rec->nr_packets	= 0;
	rec->nr_octets	= 0;
	rec->first_ms	= htonl(jiffies_to_msecs(jiffies));
	rec->last_ms	= htonl(jiffies_to_msecs(jiffies));
	rec->s_port	= userport;
	rec->d_port	= natport;
	rec->tcp_flags	= (flags == 0) ? TCP_SYN_ACK : TCP_FIN_RST;
	rec->protocol	= proto;
	rec->tos	= 0;
	rec->s_as	= userport;
	rec->d_as	= natport;
	rec->s_mask	= 0;
	rec->d_mask	= 0;

	if (pdu_data_records == NETFLOW5_RECORDS_MAX)
		netflow_export_pdu_v5();

	spin_unlock_bh(&nfsend_lock);
}

static void nf_send_timer_callback(struct timer_list *timer)
{
	(void)timer;
	if (READ_ONCE(nat_exiting))
		return;
	spin_lock_bh(&nfsend_lock);
	netflow_export_pdu_v5();
	mod_timer(&nf_send_timer, jiffies + msecs_to_jiffies(1000));
	spin_unlock_bh(&nfsend_lock);
}

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

int xt_nat_netflow_init(const char *dest)
{
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
