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
#include <net/tcp.h>
#include <net/ipv6.h>
#include "compat.h"
#include "xt_NAT.h"

/*
 * xt_NAT: Full Cone NAT (IPv4 + IPv6)
 *
 * 规则匹配后进入本 target：SNAT 改写源地址/端口为池内地址；DNAT 按会话表改写目的地址/端口。
 * IPv4: 会话存于 ht_inner(内网addr:port) 与 ht_outer(池addr:port)，由定时器按 timeout 清理。
 * IPv6: 会话存于全局链表 nat6_sessions，同样按 timeout 清理。
 * 本模块不依赖 conntrack，需在 raw 表对相关流做 CT --notrack。
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define XT_NAT_PROC_OPS struct proc_ops
#define XT_NAT_PROC_OPEN .proc_open
#define XT_NAT_PROC_READ .proc_read
#define XT_NAT_PROC_LSEEK .proc_lseek
#define XT_NAT_PROC_RELEASE .proc_release
#else
#define XT_NAT_PROC_OPS struct file_operations
#define XT_NAT_PROC_OPEN .open
#define XT_NAT_PROC_READ .read
#define XT_NAT_PROC_LSEEK .llseek
#define XT_NAT_PROC_RELEASE .release
#endif

#define FLAG_REPLIED   (1 << 0) /* 000001 */
#define FLAG_TCP_FIN   (1 << 1) /* 000010 */

#define TCP_SYN_ACK 0x12
#define TCP_FIN_RST 0x05

static LIST_HEAD(usock_list);
static int sndbuf = 1310720;
static int engine_id = 0;
static unsigned int pdu_data_records = 0;
static unsigned int pdu_seq = 0;
struct netflow5_pdu pdu;

static DEFINE_SPINLOCK(nfsend_lock);

static atomic64_t sessions_active = ATOMIC_INIT(0);
static atomic64_t sessions_tried = ATOMIC_INIT(0);
static atomic64_t sessions_created = ATOMIC_INIT(0);
static atomic64_t dnat_dropped = ATOMIC_INIT(0);
static atomic64_t frags = ATOMIC_INIT(0);
static atomic64_t related_icmp = ATOMIC_INIT(0);

static char nat_pool_buf[128] = "127.0.0.1-127.0.0.1";
static char *nat_pool = nat_pool_buf;
module_param(nat_pool, charp, 0444);
MODULE_PARM_DESC(nat_pool, "NAT pool range (addr_start-addr_end), default = 127.0.0.1-127.0.0.1");

static char nat_pool6_buf[256] = "fd00::1-fd00::1";
static char *nat_pool6 = nat_pool6_buf;
module_param(nat_pool6, charp, 0444);
MODULE_PARM_DESC(nat_pool6, "IPv6 NAT pool range (addr_start-addr_end), default = fd00::1-fd00::1");

static int nat_hash_size = 1024 * 1024;
module_param(nat_hash_size, int, 0444);
MODULE_PARM_DESC(nat_hash_size, "nat hash size, default = 256k");


static bool nat_log_verbose;
module_param(nat_log_verbose, bool, 0644);
MODULE_PARM_DESC(nat_log_verbose, "Log every NAT/NAT6 session assignment (default = false)");

static char nf_dest_buf[128] = "";
static char *nf_dest = nf_dest_buf;
module_param(nf_dest, charp, 0444);
MODULE_PARM_DESC(nf_dest, "Netflow v5 collectors (addr1:port1[,addr2:port2]), default = none");

u_int32_t nat_htable_vector = 0;

static spinlock_t *create_session_lock;

static DEFINE_SPINLOCK(sessions_timer_lock);
static struct timer_list sessions_cleanup_timer, nf_send_timer;
static bool nat_exiting; /* 模块卸载标志，阻止定时器自重启 */

struct proc_dir_entry *proc_net_nat;

struct netflow_sock {
    struct list_head list;
    struct socket *sock;
    struct sockaddr_storage addr;   // destination
};

/* IPv4 会话哈希表：按 (proto, addr, port) 哈希 */
struct xt_nat_htable {
    uint32_t use;
    spinlock_t lock;
    struct hlist_head session;
};

/* IPv4 表项：addr/port 为表键（inner 表=内网，outer 表=池），data 为会话详情 */
struct nat_htable_ent {
    struct rcu_head rcu;
    struct hlist_node list_node;
    uint8_t  proto;
    uint32_t addr;
    uint16_t port;
    struct nat_session *data;
};

struct nat_session {
    uint32_t in_addr;
    uint16_t in_port;
    uint32_t out_addr;
    uint16_t out_port;
    int16_t  timeout;
    uint8_t  flags;
};

/* IPv6 会话数据（inner 与 outer 表项共享） */
struct nat6_session_data {
    struct in6_addr in_addr;
    uint16_t in_port;
    struct in6_addr out_addr;
    uint16_t out_port;
    int16_t  timeout;
    uint8_t  flags;
};

/* IPv6 哈希表项：键为 (proto, addr, port)；inner 表=内网，outer 表=池 */
struct nat6_htable_ent {
    struct rcu_head rcu;
    struct hlist_node list_node;
    struct hlist_node addr_list_node; /* ht6_outer_by_addr 辅助索引链 */
    uint8_t  proto;
    struct in6_addr addr;
    uint16_t port;
    struct nat6_session_data *data;
};


static u_int32_t nat_pool_start;
static u_int32_t nat_pool_end;
static struct in6_addr nat_pool6_start;
static struct in6_addr nat_pool6_end;
static struct in6_addr nat_pool6_range;
static u8 nat_pool6_range_bits;

/* IPv4: inner 表键=内网 addr:port（SNAT 查），outer 表键=池 addr:port（DNAT 查） */
struct xt_nat_htable *ht_inner, *ht_outer;

/* IPv6: 与 IPv4 相同的双哈希表结构，复用 xt_nat_htable 桶类型 */
static struct xt_nat_htable *ht6_inner, *ht6_outer;
static int nat6_hash_size = 64 * 1024;

/* P0-2: (proto, addr) 辅助哈希索引，避免 lookup_nat6_outer_by_addr 全表扫描 */
static struct xt_nat_htable *ht6_outer_by_addr;

/* IPv6 哈希表向量，用于分批清理（与 IPv4 的 nat_htable_vector 类似） */
static u_int32_t nat6_htable_vector;

/* P0-1: Per-NAT-IP 端口 bitmap，将端口分配从 O(N) 降为 O(1) */
#define PORT_BITMAP_BITS  65536
#define PORT_BITMAP_PROTOS 3  /* TCP=0, UDP=1, ICMP=2 */
static unsigned long **port_bitmaps; /* [pool_size * PORT_BITMAP_PROTOS] */

/* P1-2: IPv6 create_session 哈希锁，防止并发端口冲突 */
#define NAT6_CREATE_LOCK_BITS 10
#define NAT6_CREATE_LOCK_SIZE (1 << NAT6_CREATE_LOCK_BITS)
static spinlock_t create_session6_lock[NAT6_CREATE_LOCK_SIZE];

/* P3-1: 专用 slab cache，减少 GFP_ATOMIC 碎片化 */
static struct kmem_cache *nat_session_cachep;
static struct kmem_cache *nat_htable_ent_cachep;
static struct kmem_cache *nat6_session_data_cachep;
static struct kmem_cache *nat6_htable_ent_cachep;

static char *print_sockaddr(const struct sockaddr_storage *ss)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "%pISpc", ss);
    return buf;
}

static inline u_int32_t
get_pool_size(void)
{
    return ntohl(nat_pool_end)-ntohl(nat_pool_start)+1;
}

static inline u_int32_t
get_random_nat_addr(void)
{
    return htonl(ntohl(nat_pool_start) + reciprocal_scale(get_random_u32(), get_pool_size()));
}

/* IPv6 地址按大端逐字节比较/加减，用于池范围与随机 offset 计算 */
static inline int in6_addr_cmp_raw(const struct in6_addr *a, const struct in6_addr *b)
{
    return memcmp(a->s6_addr, b->s6_addr, sizeof(a->s6_addr));
}

static inline void in6_addr_sub_raw(const struct in6_addr *a, const struct in6_addr *b, struct in6_addr *res)
{
    int i;
    int borrow = 0;

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

static inline void in6_addr_add_raw(const struct in6_addr *a, const struct in6_addr *b, struct in6_addr *res)
{
    int i;
    int carry = 0;

    for (i = 15; i >= 0; i--) {
        int sum = (int)a->s6_addr[i] + (int)b->s6_addr[i] + carry;

        res->s6_addr[i] = (u8)(sum & 0xff);
        carry = sum >> 8;
    }
}

/* 返回表示 addr 所需最少位数（最高位 1 到最低位的位数），用于随机 offset 的位宽 */
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

/* 解析模块参数 nat_pool6（格式 "start-end"），填 nat_pool6_start/end/range 与 range_bits */
static int parse_nat_pool6(void)
{
    char start_buf[128] = { 0 };
    char end_buf[128] = { 0 };
    const char *sep;
    size_t left_len, right_len;

    sep = strchr(nat_pool6, '-');
    if (!sep)
        return -EINVAL;

    left_len = sep - nat_pool6;
    right_len = strnlen(sep + 1, sizeof(end_buf) - 1);
    if (left_len == 0 || left_len >= sizeof(start_buf))
        return -EINVAL;
    if (right_len == 0 || right_len >= sizeof(end_buf))
        return -EINVAL;

    memcpy(start_buf, nat_pool6, left_len);
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

/* 检查 addr 是否在 [nat_pool6_start, nat_pool6_end] 内（含边界） */
static inline bool in6_addr_in_pool6_range(const struct in6_addr *addr)
{
    return in6_addr_cmp_raw(&nat_pool6_start, addr) <= 0 &&
           in6_addr_cmp_raw(addr, &nat_pool6_end) <= 0;
}

/*
 * 在 [nat_pool6_start, nat_pool6_end] 内均匀随机一个地址写入 addr。
 * 做法：随机 offset ∈ [0, range]，然后 addr = start + offset；非 2 幂范围用拒绝采样。
 */
static inline void
get_random_nat_addr6(struct in6_addr *addr)
{
    struct in6_addr offset;
    int leading_zero_bits;
    int zero_bytes;
    int zero_bits_remainder;

    if (nat_pool6_range_bits == 0) {
        *addr = nat_pool6_start;
        return;
    }

    do {
        get_random_bytes(offset.s6_addr, sizeof(offset.s6_addr));
        leading_zero_bits = 128 - nat_pool6_range_bits;
        zero_bytes = leading_zero_bits / 8;
        zero_bits_remainder = leading_zero_bits % 8;

        /*
         * offset 的高 leading_zero_bits 位必须为 0，其余保留随机值。
         * 字节布局（大端）：[0 .. zero_bytes-1] 全清零，
         * s6_addr[zero_bytes] 掩掉高 zero_bits_remainder 位，
         * s6_addr[zero_bytes+1 .. 15] 保留随机值（属于有效范围内的低位）。
         */
        if (zero_bytes > 0)
            memset(offset.s6_addr, 0, zero_bytes);
        if (zero_bits_remainder)
            offset.s6_addr[zero_bytes] &= (u8)(0xFF >> zero_bits_remainder);
    } while (in6_addr_cmp_raw(&offset, &nat_pool6_range) > 0);

    in6_addr_add_raw(&nat_pool6_start, &offset, addr);

    /* 防御性检查：确保生成的地址绝不超出池范围，避免使用未配置地址导致 bind EINVAL */
    if (unlikely(!in6_addr_in_pool6_range(addr))) {
        printk(KERN_WARNING "xt_NAT IPv6: generated address out of pool range, using pool start\n");
        *addr = nat_pool6_start;
    }
}

static inline u_int32_t
get_hash_nat_ent(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    return reciprocal_scale(jhash_3words((u32)proto, addr, (u32)port, 0), nat_hash_size);
}

static inline u_int32_t
get_hash_nat6_ent(const uint8_t proto, const struct in6_addr *addr, const uint16_t port)
{
    u32 a = jhash2((const u32 *)addr->s6_addr, 4, (u32)proto);
    return reciprocal_scale(jhash_2words(a, (u32)port, 0), nat6_hash_size);
}

/* P0-2: 仅 (proto, addr) 的哈希，用于 ICMPv6 非 ECHO 的辅助索引 */
static inline u_int32_t
get_hash_nat6_addr(const uint8_t proto, const struct in6_addr *addr)
{
    u32 a = jhash2((const u32 *)addr->s6_addr, 4, (u32)proto);
    return reciprocal_scale(a, nat6_hash_size);
}

/* P1-2: IPv6 NAT 地址 → 锁桶索引 */
static inline unsigned int nat6_addr_lock_hash(const struct in6_addr *addr)
{
    return jhash2((const u32 *)addr->s6_addr, 4, 0) & (NAT6_CREATE_LOCK_SIZE - 1);
}

/* P0-1: 协议号 → bitmap 索引 */
static inline int proto_to_bitmap_idx(uint8_t proto)
{
    switch (proto) {
    case IPPROTO_TCP:  return 0;
    case IPPROTO_UDP:  return 1;
    case IPPROTO_ICMP: return 2;
    default:           return -1;
    }
}

static inline unsigned long *get_port_bitmap(unsigned int nataddr_id, uint8_t proto)
{
    int idx = proto_to_bitmap_idx(proto);
    if (idx < 0 || !port_bitmaps)
        return NULL;
    return port_bitmaps[nataddr_id * PORT_BITMAP_PROTOS + idx];
}

/* P3-1: RCU 延迟释放回调 */
static void nat_ent_rcu_free(struct rcu_head *head)
{
    kmem_cache_free(nat_htable_ent_cachep,
                    container_of(head, struct nat_htable_ent, rcu));
}

static void nat6_ent_rcu_free(struct rcu_head *head)
{
    kmem_cache_free(nat6_htable_ent_cachep,
                    container_of(head, struct nat6_htable_ent, rcu));
}

static inline u_int32_t pool_table_create(void)
{
    unsigned int sz;
    unsigned int pool_size;
    unsigned int total_bitmaps;
    int i;

    pool_size = get_pool_size();

    sz = sizeof(spinlock_t) * pool_size;
    create_session_lock = kzalloc(sz, GFP_KERNEL);

    if (create_session_lock == NULL)
        return -ENOMEM;

    for (i = 0; i < pool_size; i++) {
        spin_lock_init(&create_session_lock[i]);
    }

    printk(KERN_INFO "xt_NAT DEBUG: nat pool table mem: %d\n", sz);

    /* P0-1: 为每个 (nataddr, proto) 分配端口 bitmap */
    total_bitmaps = pool_size * PORT_BITMAP_PROTOS;
    port_bitmaps = kzalloc(sizeof(unsigned long *) * total_bitmaps, GFP_KERNEL);
    if (!port_bitmaps) {
        kfree(create_session_lock);
        create_session_lock = NULL;
        return -ENOMEM;
    }
    for (i = 0; i < total_bitmaps; i++) {
        port_bitmaps[i] = kvzalloc(BITS_TO_LONGS(PORT_BITMAP_BITS) * sizeof(unsigned long), GFP_KERNEL);
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
           (unsigned long)total_bitmaps * BITS_TO_LONGS(PORT_BITMAP_BITS) * sizeof(unsigned long),
           total_bitmaps);

    return 0;
}

void pool_table_remove(void)
{
    if (port_bitmaps) {
        unsigned int total = get_pool_size() * PORT_BITMAP_PROTOS;
        unsigned int i;
        for (i = 0; i < total; i++)
            kvfree(port_bitmaps[i]);
        kfree(port_bitmaps);
        port_bitmaps = NULL;
    }
    if (!create_session_lock)
        return;
    kfree(create_session_lock);
    create_session_lock = NULL;
    printk(KERN_INFO "xt_NAT pool_table_remove DEBUG: removed\n");
}


void nat_htable_remove(void)
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
        if (ht_inner[i].use != 0) {
            printk(KERN_WARNING "xt_NAT nat_htable_remove inner ERROR: bad use value: %u in element %d\n", ht_inner[i].use, i);
        }
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
        if (ht_outer[i].use != 0) {
            printk(KERN_WARNING "xt_NAT nat_htable_remove outer ERROR: bad use value: %u in element %d\n", ht_outer[i].use, i);
        }
        spin_unlock_bh(&ht_outer[i].lock);
    }
    }
    if (ht_inner) {
        kfree(ht_inner);
        ht_inner = NULL;
    }
    if (ht_outer) {
        kfree(ht_outer);
        ht_outer = NULL;
    }
    printk(KERN_INFO "xt_NAT nat_htable_remove DONE\n");
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

    if (ht6_inner) {
        kvfree(ht6_inner);
        ht6_inner = NULL;
    }
    if (ht6_outer) {
        kvfree(ht6_outer);
        ht6_outer = NULL;
    }
    if (ht6_outer_by_addr) {
        kvfree(ht6_outer_by_addr);
        ht6_outer_by_addr = NULL;
    }
    printk(KERN_INFO "xt_NAT nat6_htable_remove DONE\n");
}

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

    /* P0-2: (proto, addr) 辅助索引表 */
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


static int nat_htable_create(void)
{
    unsigned int sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_nat_htable) * nat_hash_size;
    ht_inner = kzalloc(sz, GFP_KERNEL);
    if (ht_inner == NULL)
        return -ENOMEM;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_inner[i].lock);
        INIT_HLIST_HEAD(&ht_inner[i].session);
        ht_inner[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: sessions htable inner mem: %d\n", sz);


    ht_outer = kzalloc(sz, GFP_KERNEL);
    if (ht_outer == NULL)
        return -ENOMEM;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_outer[i].lock);
        INIT_HLIST_HEAD(&ht_outer[i].session);
        ht_outer[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: sessions htable outer mem: %d\n", sz);
    return 0;
}

/* 在 ht（inner 或 outer）中按 (proto, addr, port) 查会话，且 data->timeout > 0 */
struct nat_htable_ent *lookup_session(struct xt_nat_htable *ht, const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    struct nat_htable_ent *session;
    struct hlist_head *head;
    unsigned int hash;

    hash = get_hash_nat_ent(proto, addr, port);
    if (ht[hash].use == 0)
        return NULL;

    head = &ht[hash].session;
    hlist_for_each_entry_rcu(session, head, list_node) {
        if (session->addr == addr && session->port == port && session->proto == proto && session->data->timeout >= 0) {
            return session;
        }
    }
    return NULL;
}

/* P0-1: 使用 bitmap O(1) 查找空闲端口，代替原 O(N) 线性扫描 */
static uint16_t search_free_l4_port(const uint8_t proto, const u_int32_t nataddr, const uint16_t userport)
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

    /* 非 TCP/UDP/ICMP 协议的回退：原线性搜索 */
    {
        uint16_t i, freeport;
        for (i = 0; i < 64512; i++) {
            freeport = ntohs(userport) + i;
            if (freeport < 1024)
                freeport += 1024;
            if (!lookup_session(ht_outer, proto, nataddr, htons(freeport)))
                return htons(freeport);
        }
    }
    return 0;
}

/* socket code */
static void nat_sk_error_report(struct sock *sk)
{
    /* clear connection refused errors if any */
    sk->sk_err = 0;

    return;
}

static struct socket *usock_open_sock(const struct sockaddr_storage *addr, void *user_data)
{
    struct socket *sock;
    int error;

    if ((error = sock_create_kern(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
        printk(KERN_WARNING "xt_NAT NEL: sock_create_kern error %d\n", -error);
        return NULL;
    }
    sock->sk->sk_allocation = GFP_ATOMIC;
    sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */
    sock->sk->sk_error_report = &nat_sk_error_report; /* clear ECONNREFUSED */
    sock->sk->sk_user_data = user_data; /* usock */

    if (sndbuf < SOCK_MIN_SNDBUF)
	sndbuf = SOCK_MIN_SNDBUF;

    if (sndbuf)
        sock->sk->sk_sndbuf = sndbuf;
    else
        sndbuf = sock->sk->sk_sndbuf;
    error = sock->ops->connect(sock, (struct sockaddr *)addr, sizeof(*addr), 0);
    if (error < 0) {
        printk(KERN_WARNING "xt_NAT NEL: error connecting UDP socket %d,"
               " don't worry, will try reconnect later.\n", -error);
        /* 不可在持有 nfsend_lock 的定时器回调里调用 sock_release（可能睡眠）；
         * 此处仅返回 NULL，失败创建的 sock 泄漏，避免卸载时卡死 */
        return NULL;
    }
    return sock;
}

static void netflow_sendmsg(void *buffer, const int len)
{
    struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
    struct kvec iov = { buffer, len };
    struct netflow_sock *usock;
    int ret;

    //printk(KERN_DEBUG "xt_NAT NEL: Netflow exporting function\n");

    list_for_each_entry(usock, &usock_list, list) {
        //printk(KERN_DEBUG "xt_NAT NEL: Exporting PDU to collector N\n");
        if (!usock->sock)
            usock->sock = usock_open_sock(&usock->addr, usock);

        if (!usock->sock)
            continue;

        ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
        if (ret == -EINVAL) {
            usock->sock = NULL;
        } else if (ret == -EAGAIN) {
            printk(KERN_WARNING "xt_NAT NEL: increase sndbuf!\n");
        }
    }
}

static void netflow_export_pdu_v5(void)
{
    struct timespec64 ts;
    int pdusize;

    //printk(KERN_DEBUG "xt_NAT NEL: Forming PDU seq %d, %d records\n", pdu_seq, pdu_data_records);

    if (!pdu_data_records)
        return;

    pdu.version		= htons(5);
    pdu.nr_records	= htons(pdu_data_records);
    pdu.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
    ktime_get_real_ts64(&ts);
    pdu.ts_usecs		= htonl((u32)ts.tv_sec);
    pdu.ts_unsecs	= htonl((u32)(ts.tv_nsec / 1000));
    pdu.seq		= htonl(pdu_seq);
    //pdu.v5.eng_type	= 0;
    pdu.eng_id		= (__u8)engine_id;

    pdusize = NETFLOW5_HEADER_SIZE + sizeof(struct netflow5_record) * pdu_data_records;

    netflow_sendmsg(&pdu, pdusize);

    pdu_seq += pdu_data_records;
    pdu_data_records = 0;
}

/*
 * P3-2: 使用 spin_trylock 减少数据面路径上的 nfsend_lock 争用。
 * 若锁被占用（定时器 flush 或另一 CPU 在导出），丢弃本条记录而非阻塞——
 * Netflow 本身是"尽力而为"的统计导出协议，允许丢失。
 */
static void netflow_export_flow_v5(const uint8_t proto, const u_int32_t useraddr, const uint16_t userport, const u_int32_t nataddr, const uint16_t natport, const int flags)
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
    rec->nr_packets = 0;
    rec->nr_octets	= 0;
    rec->first_ms	= htonl(jiffies_to_msecs(jiffies));
    rec->last_ms	= htonl(jiffies_to_msecs(jiffies));
    rec->s_port	= userport;
    rec->d_port	= natport;
    if (flags == 0) {
        rec->tcp_flags	= TCP_SYN_ACK;
    } else {
        rec->tcp_flags  = TCP_FIN_RST;
    }
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

/* 为 (proto, useraddr, userport) 分配池内 addr:port，建 nat_session，分别挂到 ht_inner 与 ht_outer */
struct nat_htable_ent *create_nat_session(const uint8_t proto, const u_int32_t useraddr, const uint16_t userport)
{
    unsigned int hash;
    struct nat_htable_ent *session, *session2;
    struct nat_session *data_session;
    uint16_t natport;
    u_int32_t nataddr;
    unsigned int nataddr_id;
    unsigned int attempt;
    unsigned int max_attempts;

    atomic64_inc(&sessions_tried);

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
            ret = lookup_session(ht_outer, proto, session->data->out_addr, session->data->out_port);
            spin_unlock_bh(&create_session_lock[nataddr_id]);
            return ret;
        }
        rcu_read_unlock_bh();

        if (likely(proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP)) {
            natport = search_free_l4_port(proto, nataddr, userport);
            if (natport == 0) {
                spin_unlock_bh(&create_session_lock[nataddr_id]);
                continue;
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
            printk(KERN_INFO "xt_NAT: NAT assign %pI4:%u -> %pI4:%u\n", &useraddr, ntohs(userport), &nataddr, ntohs(natport));
        data_session->timeout = 300;
        data_session->flags = 0;

        session->proto = proto;
        session->addr = useraddr;
        session->port = userport;
        session->data = data_session;

        session2->proto = proto;
        session2->addr = nataddr;
        session2->port = natport;
        session2->data = data_session;

        hash = get_hash_nat_ent(proto, useraddr, userport);
        spin_lock_bh(&ht_inner[hash].lock);
        hlist_add_head_rcu(&session->list_node, &ht_inner[hash].session);
        ht_inner[hash].use++;
        spin_unlock_bh(&ht_inner[hash].lock);

        hash = get_hash_nat_ent(proto, nataddr, natport);
        spin_lock_bh(&ht_outer[hash].lock);
        hlist_add_head_rcu(&session2->list_node, &ht_outer[hash].session);
        ht_outer[hash].use++;
        spin_unlock_bh(&ht_outer[hash].lock);

        /* P0-1: 标记端口已占用 */
        {
            unsigned long *bm = get_port_bitmap(nataddr_id, proto);
            if (bm)
                set_bit(ntohs(natport), bm);
        }

        spin_unlock_bh(&create_session_lock[nataddr_id]);

        netflow_export_flow_v5(proto, useraddr, userport, nataddr, natport, 0);

        atomic64_inc(&sessions_created);
        atomic64_inc(&sessions_active);

        /* P2-3: 直接返回已创建的 session2 指针，避免冗余哈希查找 */
        rcu_read_lock_bh();
        return session2;
    }

    printk(KERN_WARNING "xt_NAT create_nat_session ERROR: Not found free nat port for %d %pI4:%u in NAT pool\n", proto, &useraddr, userport);
    return NULL;
}

/* 在 ht6 中按 (proto, addr, port) 查会话，RCU 读端调用 */
static struct nat6_htable_ent *lookup_nat6_session(struct xt_nat_htable *ht, const uint8_t proto,
                                                    const struct in6_addr *addr, const uint16_t port)
{
    struct nat6_htable_ent *ent;
    struct hlist_head *head;
    unsigned int hash;

    hash = get_hash_nat6_ent(proto, addr, port);
    if (ht[hash].use == 0)
        return NULL;

    head = &ht[hash].session;
    hlist_for_each_entry_rcu(ent, head, list_node) {
        if (ent->proto == proto && ent->port == port &&
            ent->data->timeout >= 0 &&
            ipv6_addr_equal(&ent->addr, addr))
            return ent;
    }
    return NULL;
}

/* P0-2: 使用辅助哈希 ht6_outer_by_addr O(1) 查找，代替原 O(64K+N) 全表扫描 */
static struct nat6_htable_ent *lookup_nat6_outer_by_addr(const uint8_t proto, const struct in6_addr *addr)
{
    struct nat6_htable_ent *ent;
    struct hlist_head *head;
    unsigned int hash;

    if (unlikely(!ht6_outer_by_addr))
        return NULL;

    hash = get_hash_nat6_addr(proto, addr);
    if (ht6_outer_by_addr[hash].use == 0)
        return NULL;

    head = &ht6_outer_by_addr[hash].session;
    hlist_for_each_entry_rcu(ent, head, addr_list_node) {
        if (ent->proto == proto && ent->data->timeout >= 0 &&
            ipv6_addr_equal(&ent->addr, addr))
            return ent;
    }
    return NULL;
}

/* P0-1: 随机起始偏移减少冲突概率，平均情况显著改善 */
static uint16_t search_free_l4_port6(const uint8_t proto, const struct in6_addr *nataddr, const uint16_t userport)
{
    uint16_t i, freeport;
    uint16_t start = ntohs(userport);
    uint16_t offset = (uint16_t)(get_random_u32() % 64512);

    if (start < 1024)
        start = 1024;

    for (i = 0; i < 64512; i++) {
        freeport = 1024 + ((start - 1024 + offset + i) % 64512);
        if (!lookup_nat6_session(ht6_outer, proto, nataddr, htons(freeport)))
            return htons(freeport);
    }
    return 0;
}

/*
 * 为 (proto, useraddr, userport) 分配池内地址与端口，插入 ht6_inner + ht6_outer。
 * 返回 outer 表项指针（用于 SNAT 后续获取 out_addr/out_port）。
 *
 * 端口搜索在锁外完成（O(N) 最坏），锁内仅做 O(1) 验证 + 插入，
 * 避免 create_session6_lock 持锁时间随会话数线性增长。
 */
static struct nat6_htable_ent *create_nat6_session(const uint8_t proto, const struct in6_addr *useraddr, const uint16_t userport)
{
    struct nat6_session_data *data;
    struct nat6_htable_ent *ent_inner, *ent_outer;
    struct in6_addr nataddr;
    uint16_t natport;
    unsigned int attempt, max_attempts, hash;
    unsigned int lock_idx;

    atomic64_inc(&sessions_tried);

    max_attempts = (nat_pool6_range_bits == 0) ? 1 : 32;

    for (attempt = 0; attempt < max_attempts; attempt++) {
        get_random_nat_addr6(&nataddr);

        /*
         * 阶段 1：锁外乐观搜索（RCU 保护，无自旋锁）
         * 检查 inner 是否已有会话，并搜索候选空闲端口。
         */
        rcu_read_lock_bh();
        ent_inner = lookup_nat6_session(ht6_inner, proto, useraddr, userport);
        if (ent_inner) {
            struct nat6_htable_ent *ret;
            ret = lookup_nat6_session(ht6_outer, proto, &ent_inner->data->out_addr, ent_inner->data->out_port);
            /* 保持 rcu_read_lock_bh — 调用方负责 unlock */
            return ret;
        }

        if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMPV6) {
            natport = search_free_l4_port6(proto, &nataddr, userport);
            rcu_read_unlock_bh();
            if (natport == 0)
                continue;
        } else {
            rcu_read_unlock_bh();
            natport = userport;
        }

        /*
         * 阶段 2：加锁后验证（O(1) — 单次 lookup）
         * 确认端口未被并发线程抢占，且 inner 仍不存在。
         */
        lock_idx = nat6_addr_lock_hash(&nataddr);
        spin_lock_bh(&create_session6_lock[lock_idx]);

        rcu_read_lock_bh();
        ent_inner = lookup_nat6_session(ht6_inner, proto, useraddr, userport);
        if (unlikely(ent_inner)) {
            struct nat6_htable_ent *ret;
            ret = lookup_nat6_session(ht6_outer, proto, &ent_inner->data->out_addr, ent_inner->data->out_port);
            spin_unlock_bh(&create_session6_lock[lock_idx]);
            return ret;
        }

        if (lookup_nat6_session(ht6_outer, proto, &nataddr, natport)) {
            rcu_read_unlock_bh();
            spin_unlock_bh(&create_session6_lock[lock_idx]);
            continue;
        }
        rcu_read_unlock_bh();

        /*
         * 阶段 3：分配并插入（锁内，但无 O(N) 搜索）
         */
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

        data->in_addr = *useraddr;
        data->in_port = userport;
        data->out_addr = nataddr;
        data->out_port = natport;
        data->timeout = 300;
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
        hlist_add_head_rcu(&ent_inner->list_node, &ht6_inner[hash].session);
        ht6_inner[hash].use++;
        spin_unlock_bh(&ht6_inner[hash].lock);

        hash = get_hash_nat6_ent(proto, &nataddr, natport);
        spin_lock_bh(&ht6_outer[hash].lock);
        hlist_add_head_rcu(&ent_outer->list_node, &ht6_outer[hash].session);
        ht6_outer[hash].use++;
        spin_unlock_bh(&ht6_outer[hash].lock);

        hash = get_hash_nat6_addr(proto, &nataddr);
        spin_lock_bh(&ht6_outer_by_addr[hash].lock);
        hlist_add_head_rcu(&ent_outer->addr_list_node, &ht6_outer_by_addr[hash].session);
        ht6_outer_by_addr[hash].use++;
        spin_unlock_bh(&ht6_outer_by_addr[hash].lock);

        spin_unlock_bh(&create_session6_lock[lock_idx]);

        if (nat_log_verbose)
            printk(KERN_INFO "xt_NAT: NAT6 assign %pI6:%u -> %pI6:%u\n",
                   useraddr, ntohs(userport), &nataddr, ntohs(natport));

        atomic64_inc(&sessions_created);
        atomic64_inc(&sessions_active);

        rcu_read_lock_bh();
        return ent_outer;
    }
    return NULL;
}

/*
 * IPv4 target：SNAT 时按 (saddr, sport) 查 inner 表，无则 create_nat_session，改写为池 addr:port；
 * DNAT 时按 (daddr, dport) 查 outer 表，改写为目的内网 addr:port。
 */
static unsigned int
nat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    struct nat_htable_ent *session;
    uint16_t nat_port;
    skb_frag_t *frag;
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
        //printk(KERN_DEBUG "xt_NAT SNAT: tg = SNAT, random outer NAT IP per new session");
        //printk(KERN_DEBUG "xt_NAT SNAT: check IPv4 packet with src ip = %pI4 and dst ip = %pI4\n", &ip->saddr, &ip->daddr);

        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated TCP packet\n");
                return NF_DROP;
            }
            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            //printk(KERN_DEBUG "xt_NAT SNAT: TCP packet with src port = %d\n", ntohs(tcp->source));
            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, tcp->source);
            if (session) {
                //printk(KERN_DEBUG "xt_NAT SNAT: found session for src ip = %pI4 and src port = %d and nat port = %d\n", &ip->saddr, ntohs(tcp->source), ntohs(session->data->out_port));

                csum_replace4(&ip->check, ip->saddr, session->data->out_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->data->out_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->data->out_port, true);

                ip->saddr = session->data->out_addr;
                tcp->source = session->data->out_port;

                /*					if (session->data->flags & FLAG_TCP_CLOSED) {
                						session->data->timeout=5;
                					} else if (tcp->rst || tcp->fin) {
                						session->data->flags |= FLAG_TCP_CLOSED;
                						session->data->timeout=5;
                					} else

                */
                if (tcp->fin || tcp->rst) {
                    session->data->timeout=10;
                    session->data->flags |= FLAG_TCP_FIN;
                } else if (session->data->flags & FLAG_TCP_FIN) {
                    session->data->timeout=10;
                    session->data->flags &= ~FLAG_TCP_FIN;
                } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=300;
                }

                /*
                					if ((session->data->flags & FLAG_REPLIED) == 0) {
                                                                session->data->timeout=30;
                                                        } else {
                                                                session->data->timeout=300;
                                                        }
                */

                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                //printk(KERN_DEBUG "xt_NAT SNAT: NOT found session for src ip = %pI4 and src port = %d\n", &ip->saddr, ntohs(tcp->source));

                /*                                      if (!tcp->syn) {
                                                                //printk(KERN_DEBUG "xt_NAT SNAT: SYN flag is not set. Dropping packet\n");
                                                                return NF_DROP;
                                                        }
                */
                session = create_nat_session(ip->protocol, ip->saddr, tcp->source);
                if (session == NULL) {
                    printk(KERN_NOTICE "xt_NAT SNAT: Cannot create new session. Dropping packet\n");
                    return NF_DROP;
                }

                csum_replace4(&ip->check, ip->saddr, session->addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, session->data->in_port, session->data->out_port, true);
                ip->saddr = session->addr;
                tcp->source = session->data->out_port;
                rcu_read_unlock_bh();
                //return NF_ACCEPT;
            }

        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated UDP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            //printk(KERN_DEBUG "xt_NAT SNAT: UDP packet with src port = %d\n", ntohs(udp->source));

            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, udp->source);
            if (session) {
                //printk(KERN_DEBUG "xt_NAT SNAT: found session for src ip = %pI4 and src port = %d and nat port = %d\n", &ip->saddr, ntohs(udp->source), ntohs(session->data->out_port));

                csum_replace4(&ip->check, ip->saddr, session->data->out_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->data->out_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->source, session->data->out_port, true);
                }

                ip->saddr = session->data->out_addr;
                udp->source = session->data->out_port;

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=300;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                //printk(KERN_DEBUG "xt_NAT SNAT: NOT found session for src ip = %pI4 and src port = %d\n", &ip->saddr, ntohs(udp->source));

                session = create_nat_session(ip->protocol, ip->saddr, udp->source);
                if (session == NULL) {
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
                //return NF_ACCEPT;
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated ICMP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            icmp = (struct icmphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            //printk(KERN_DEBUG "xt_NAT SNAT: ICMP packet with type = %d and code = %d\n", icmp->type, icmp->code);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            } else if (icmp->type == 3 || icmp->type == 4 || icmp->type == 5 || icmp->type == 11 || icmp->type == 12 || icmp->type == 31) {

            }

            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, nat_port);
            if (session) {
                //printk(KERN_DEBUG "xt_NAT SNAT: found session for src ip = %pI4 and icmp id = %d\n", &ip->saddr, ntohs(nat_port));

                csum_replace4(&ip->check, ip->saddr, session->data->out_addr);

                ip->saddr = session->data->out_addr;

                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->out_port, true);
                    icmp->un.echo.id = session->data->out_port;
                }

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=30;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                //printk(KERN_DEBUG "xt_NAT SNAT: NOT found session for src ip = %pI4 and icmp id = %d\n",&ip->saddr, ntohs(nat_port));

                session = create_nat_session(ip->protocol, ip->saddr, nat_port);
                if (session == NULL) {
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
                //return NF_ACCEPT;
            }
        } else {
            //skb_set_transport_header(skb, ip->ihl * 4);

            //printk(KERN_DEBUG "xt_NAT SNAT: Generic IP packet\n");

            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, 0);
            if (session) {
                //printk(KERN_DEBUG "xt_NAT SNAT: found session for src ip = %pI4\n", &ip->saddr);

                csum_replace4(&ip->check, ip->saddr, session->data->out_addr);

                ip->saddr = session->data->out_addr;

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=300;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                //printk(KERN_DEBUG "xt_NAT SNAT: NOT found session for src ip = %pI4\n",&ip->saddr);

                session = create_nat_session(ip->protocol, ip->saddr, 0);
                if (session == NULL) {
                    printk(KERN_NOTICE "xt_NAT SNAT: Cannot create new session. Dropping packet\n");
                    return NF_DROP;
                }

                csum_replace4(&ip->check, ip->saddr, session->addr);
                ip->saddr = session->addr;
                rcu_read_unlock_bh();
                //return NF_ACCEPT;
            }
        }
    } else if (info->variant == XTNAT_DNAT) {
        //printk(KERN_DEBUG "xt_NAT DNAT: tg = DNAT, outer NAT IP = %pI4", &ip->daddr);
        //printk(KERN_DEBUG "xt_NAT DNAT: check IPv4 packet with src ip = %pI4 and dst nat ip = %pI4\n", &ip->saddr, &ip->daddr);

        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated TCP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            if (unlikely(skb_shinfo(skb)->nr_frags > 1 && skb_headlen(skb) == sizeof(struct iphdr))) {
                frag = &skb_shinfo(skb)->frags[0];
                //printk(KERN_DEBUG "xt_NAT DNAT: frag_size = %u (required %lu)\n", skb_frag_size(frag), sizeof(struct tcphdr));
                if (unlikely(skb_frag_size(frag) < sizeof(struct tcphdr))) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop TCP frag_size = %u\n", skb_frag_size(frag));
                        return NF_DROP;
                }
                tcp = (struct tcphdr *)skb_frag_address_safe(frag);
                if (unlikely(tcp == NULL)) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop fragmented TCP\n");
                        return NF_DROP;
                }
                atomic64_inc(&frags);
            }

            //printk(KERN_DEBUG "xt_NAT DNAT: TCP packet with dst port = %d\n", ntohs(tcp->dest));

            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, tcp->dest);
            if (likely(session)) {
                //printk(KERN_DEBUG "xt_NAT DNAT: found session for src ip = %pI4 and src port = %d and nat port = %d\n", &session->data->in_addr, ntohs(session->data->in_port), ntohs(tcp->dest));
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->daddr, session->data->in_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->dest, session->data->in_port, true);
                ip->daddr = session->data->in_addr;
                tcp->dest = session->data->in_port;

                if (tcp->fin || tcp->rst) {
                    session->data->timeout=10;
                    session->data->flags |= FLAG_TCP_FIN;
                } else if (session->data->flags & FLAG_TCP_FIN) {
                    session->data->timeout=10;
                    session->data->flags &= ~FLAG_TCP_FIN;
                } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                    //printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                    session->data->timeout=300;
                    session->data->flags |= FLAG_REPLIED;
                }

                /*					if (((session->data->flags & FLAG_TCP_CLOSED) == 0) && (tcp->rst || tcp->fin)) {
                						session->data->flags |= FLAG_TCP_CLOSED;
                						session->data->timeout=5;
                					} else if (((session->data->flags & FLAG_REPLIED) == 0) && (session->data->flags & FLAG_TCP_CLOSED) == 0) {
                						//printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                						session->data->timeout=300;
                						session->data->flags |= FLAG_REPLIED;
                					}
                */
                /*					if ((session->data->flags & FLAG_REPLIED) == 0 && (tcp->rst || tcp->fin)) {
                						session->data->timeout=5;
                					} else if ((session->data->flags & FLAG_REPLIED) == 0) {
                						//printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                						session->data->timeout=300;
                						session->data->flags |= FLAG_REPLIED;
                					}
                */
                /*
                                                        if ((session->data->flags & FLAG_REPLIED) == 0) {
                                                                //printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                                                                session->data->timeout=300;
                                                                session->data->flags |= FLAG_REPLIED;
                                                        }
                */
                //printk(KERN_DEBUG "xt_NAT DNAT: new dst ip = %pI4 and dst port = %d\n", &ip->daddr, ntohs(tcp->dest));
                //printk(KERN_DEBUG "xt_NAT DNAT: new src ip = %pI4 and src port = %d\n", &ip->saddr, ntohs(tcp->source));
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
                //printk(KERN_DEBUG "xt_NAT DNAT: NOT found session for nat ip = %pI4 and nat port = %d\n", &ip->daddr, ntohs(tcp->dest));
                //return NF_DROP;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated UDP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            if (unlikely(skb_shinfo(skb)->nr_frags > 1 && skb_headlen(skb) == sizeof(struct iphdr))) {
                frag = &skb_shinfo(skb)->frags[0];
                //printk(KERN_DEBUG "xt_NAT DNAT: frag_size = %u (required %lu)\n", skb_frag_size(frag), sizeof(struct udphdr));
                if (unlikely(skb_frag_size(frag) < sizeof(struct udphdr))) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop UDP frag_size = %u\n", skb_frag_size(frag));
                        return NF_DROP;
                }
                udp = (struct udphdr *)skb_frag_address_safe(frag);
                if (unlikely(udp == NULL)) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop fragmented UDP\n");
                        return NF_DROP;
                }
                atomic64_inc(&frags);
            }

            //printk(KERN_DEBUG "xt_NAT DNAT: UDP packet with dst port = %d\n", ntohs(udp->dest));

            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, udp->dest);
            if (likely(session)) {
                //printk(KERN_DEBUG "xt_NAT DNAT: found session for src ip = %pI4 and src port = %d and nat port = %d\n", &session->data->in_addr, ntohs(session->data->in_port), ntohs(udp->dest));
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->daddr, session->data->in_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->dest, session->data->in_port, true);
                }
                ip->daddr = session->data->in_addr;
                udp->dest = session->data->in_port;

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    //printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                    session->data->timeout=300;
                    session->data->flags |= FLAG_REPLIED;
                }

                //printk(KERN_DEBUG "xt_NAT DNAT: new dst ip = %pI4 and dst port = %d\n", &ip->daddr, ntohs(udp->dest));
                //printk(KERN_DEBUG "xt_NAT DNAT: new src ip = %pI4 and src port = %d\n", &ip->saddr, ntohs(udp->source));
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
                //printk(KERN_DEBUG "xt_NAT DNAT: NOT found session for nat ip = %pI4 and nat port = %d\n", &ip->daddr, ntohs(udp->dest));
                //return NF_DROP;
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated ICMP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            icmp = (struct icmphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);
            //printk(KERN_DEBUG "xt_NAT DNAT: ICMP packet with type = %d and code = %d\n", icmp->type, icmp->code);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            } else if (icmp->type == 3 || icmp->type == 4 || icmp->type == 5 || icmp->type == 11 || icmp->type == 12 || icmp->type == 31) {
                atomic64_inc(&related_icmp);
                //printk(KERN_DEBUG "xt_NAT DNAT: Len: skb=%d, iphdr=%d\n",skb->len, ip_hdrlen(skb));
                if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr)) {
                    printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated IP header\n");
                    return NF_DROP;
                }

                skb_set_network_header(skb,sizeof(struct icmphdr) + sizeof(struct iphdr));
                ip = (struct iphdr *)skb_network_header(skb);
                skb_reset_network_header(skb);

                //printk(KERN_DEBUG "xt_NAT DNAT: Related ICMP\n");
                //printk(KERN_DEBUG "xt_NAT DNAT: Second IP HDR: proto = %d and saddr = %pI4 and daddr = %pI4\n", ip->protocol, &ip->saddr, &ip->daddr);

                if (ip->protocol == IPPROTO_TCP) {
                    //printk(KERN_DEBUG "xt_NAT DNAT: Related TCP len: skb=%d, iphdr=%d\n",skb->len, ip_hdrlen(skb));
                    if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                        printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated TCP header\n");
                        return NF_DROP;
                    }
                    skb_set_transport_header(skb, (ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    tcp = (struct tcphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    //port = tcp->source;
                    //printk(KERN_DEBUG "xt_NAT DNAT: TCP packet with source nat port = %d\n", ntohs(tcp->source));
                    rcu_read_lock_bh();
                    session = lookup_session(ht_outer, ip->protocol, ip->saddr, tcp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->data->in_addr);
                        //inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->data->in_addr, true);
                        //inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->data->in_port, true);
                        ip->saddr = session->data->in_addr;
                        tcp->source = session->data->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }

                    //skb_reset_network_header(skb);
                    ip = (struct iphdr *)skb_network_header(skb);

                    csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                    ip->daddr = session->data->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_UDP) {
                    //printk(KERN_DEBUG "xt_NAT DNAT: Related UDP len: skb=%d, iphdr=%d\n",skb->len, ip_hdrlen(skb));
                    if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                        printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated UDP header\n");
                        return NF_DROP;
                    }

                    skb_set_transport_header(skb, (ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    udp = (struct udphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    //printk(KERN_DEBUG "xt_NAT DNAT: UDP packet with source nat port = %d\n", ntohs(udp->source));

                    rcu_read_lock_bh();
                    session = lookup_session(ht_outer, ip->protocol, ip->saddr, udp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->data->in_addr);
                        //inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->data->in_addr, true);
                        //inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->data->in_port, true);
                        ip->saddr = session->data->in_addr;
                        udp->source = session->data->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }

                    //skb_reset_network_header(skb);
                    ip = (struct iphdr *)skb_network_header(skb);

                    csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                    ip->daddr = session->data->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_ICMP) {
                    if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                        printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated ICMP header\n");
                        return NF_DROP;
                    }

                    skb_set_transport_header(skb, (ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    icmp = (struct icmphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    //printk(KERN_DEBUG "xt_NAT DNAT: ICMP packet\n");

                    nat_port = 0;
                    if (icmp->type == 0 || icmp->type == 8) {
                        nat_port = icmp->un.echo.id;
                    }

                    rcu_read_lock_bh();
                    session = lookup_session(ht_outer, ip->protocol, ip->saddr, nat_port);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->data->in_addr);
                        //inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->data->in_addr, true);
                        //inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->data->in_port, true);
                        ip->saddr = session->data->in_addr;

                        if (icmp->type == 0 || icmp->type == 8) {
                            inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->in_port, true);
                            icmp->un.echo.id = session->data->in_port;
                        }

                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }

                    //skb_reset_network_header(skb);
                    ip = (struct iphdr *)skb_network_header(skb);

                    csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                    ip->daddr = session->data->in_addr;
                    rcu_read_unlock_bh();
                }

                return NF_ACCEPT;

            }
            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                //printk(KERN_DEBUG "xt_NAT DNAT: found session for src ip = %pI4 and icmp id = %d\n", &session->data->in_addr, ntohs(nat_port));
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                ip->daddr = session->data->in_addr;

                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->in_port, true);
                    icmp->un.echo.id = session->data->in_port;
                }

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    //printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                    session->data->timeout=30;
                    session->data->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();

                //printk(KERN_DEBUG "xt_NAT DNAT: new dst ip = %pI4 and icmp id = %d\n", &ip->daddr, ntohs(nat_port));
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
                //printk(KERN_DEBUG "xt_NAT DNAT: NOT found session for nat ip = %pI4 and icmp id = %d\n", &ip->daddr, ntohs(nat_port));
                //return NF_DROP;
            }
        } else {
            //skb_set_transport_header(skb, ip->ihl * 4);
            //printk(KERN_DEBUG "xt_NAT DNAT: Generic IP packet\n");

            nat_port = 0;
            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                //printk(KERN_DEBUG "xt_NAT DNAT: found session for src ip = %pI4 and icmp id = %d\n", &session->data->in_addr, ntohs(nat_port));
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                ip->daddr = session->data->in_addr;

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    //printk(KERN_DEBUG "xt_NAT DNAT: Changing state from UNREPLIED to REPLIED\n");
                    session->data->timeout=300;
                    session->data->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();

                //printk(KERN_DEBUG "xt_NAT DNAT: new dst ip = %pI4\n", &ip->daddr);
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
                //printk(KERN_DEBUG "xt_NAT DNAT: NOT found session for nat ip = %pI4\n", &ip->daddr);
                //return NF_DROP;
            }
        }
    }

    //printk(KERN_DEBUG "xt_NAT ----------------\n");

    return NF_ACCEPT;
}

/*
 * IPv6 target：SNAT 时按 (saddr, src_port) 查 inner，无则 create_nat6_session，改写为池 addr:port；
 * DNAT 时按 (daddr, dst_port) 查 outer，改写为目的内网 addr:port。支持 TCP/UDP/ICMPv6。
 */
static unsigned int
nat_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct ipv6hdr *ip6h;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmp6hdr *icmp6 = NULL;
    struct nat6_htable_ent *session;
    struct in6_addr new_addr;
    uint16_t new_port;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
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
    l4proto = ip6h->nexthdr; /* ipv6_skip_exthdr 要求调用方传入初始 nexthdr，否则会按垃圾值解析扩展头并返回错误 */
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

    /* 确保 IPv6 头 + L4 头区域可写（skb 可能共享/克隆） */
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
        if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST || icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
            src_port = icmp6->icmp6_identifier;
            dst_port = icmp6->icmp6_identifier;
        }
    }

    if (info->variant == XTNAT_SNAT) {
        /* 跳过 link-local / multicast 源，否则 NDP 等链路层协议会坏 */
        if (ipv6_addr_type(&ip6h->saddr) & (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_MULTICAST))
            return NF_ACCEPT;
        /* 跳过源已在池内的包，避免"池→池"的无意义 SNAT */
        if (in6_addr_in_pool6_range(&ip6h->saddr))
            return NF_ACCEPT;

        rcu_read_lock_bh();
        session = lookup_nat6_session(ht6_inner, l4proto, &ip6h->saddr, src_port);
        if (session) {
            if (l4proto == IPPROTO_TCP && tcp) {
                if (tcp->fin || tcp->rst) {
                    session->data->timeout = 10;
                    session->data->flags |= FLAG_TCP_FIN;
                } else if (session->data->flags & FLAG_TCP_FIN) {
                    session->data->timeout = 10;
                    session->data->flags &= ~FLAG_TCP_FIN;
                } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout = 30;
                } else {
                    session->data->timeout = 300;
                }
            } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                session->data->timeout = 30;
            } else {
                session->data->timeout = 300;
            }

            new_addr = session->data->out_addr;
            new_port = session->data->out_port;
            rcu_read_unlock_bh();
        } else {
            rcu_read_unlock_bh();
            session = create_nat6_session(l4proto, &ip6h->saddr, src_port);
            if (!session) {
                printk(KERN_NOTICE "xt_NAT IPv6 SNAT: Cannot create new session. Dropping packet\n");
                return NF_DROP;
            }
            new_addr = session->data->out_addr;
            new_port = session->data->out_port;
            rcu_read_unlock_bh();
        }

        if (l4proto == IPPROTO_TCP && tcp) {
            inet_proto_csum_replace16(&tcp->check, skb, (__be32 *)&ip6h->saddr, (__be32 *)&new_addr, true);
            inet_proto_csum_replace2(&tcp->check, skb, tcp->source, new_port, true);
            ip6h->saddr = new_addr;
            tcp->source = new_port;
        } else if (l4proto == IPPROTO_UDP && udp) {
            if (udp->check) {
                inet_proto_csum_replace16(&udp->check, skb, (__be32 *)&ip6h->saddr, (__be32 *)&new_addr, true);
                inet_proto_csum_replace2(&udp->check, skb, udp->source, new_port, true);
            }
            ip6h->saddr = new_addr;
            udp->source = new_port;
        } else if (l4proto == IPPROTO_ICMPV6 && icmp6) {
            inet_proto_csum_replace16(&icmp6->icmp6_cksum, skb, (__be32 *)&ip6h->saddr, (__be32 *)&new_addr, true);
            ip6h->saddr = new_addr;
            if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST || icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
                inet_proto_csum_replace2(&icmp6->icmp6_cksum, skb, icmp6->icmp6_identifier, new_port, true);
                icmp6->icmp6_identifier = new_port;
            }
        } else {
            ip6h->saddr = new_addr;
        }
    } else if (info->variant == XTNAT_DNAT) {
        rcu_read_lock_bh();
        session = lookup_nat6_session(ht6_outer, l4proto, &ip6h->daddr, dst_port);
        /* ICMPv6 非 ECHO（ND 等）无 identifier，dst_port 为 0，按 (proto, out_addr) 再试 */
        if (!session && l4proto == IPPROTO_ICMPV6 && dst_port == 0)
            session = lookup_nat6_outer_by_addr(l4proto, &ip6h->daddr);
        if (session) {
            if (l4proto == IPPROTO_TCP && tcp) {
                if (tcp->fin || tcp->rst) {
                    session->data->timeout = 10;
                    session->data->flags |= FLAG_TCP_FIN;
                } else if (session->data->flags & FLAG_TCP_FIN) {
                    session->data->timeout = 10;
                    session->data->flags &= ~FLAG_TCP_FIN;
                } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout = 300;
                    session->data->flags |= FLAG_REPLIED;
                }
            } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                session->data->timeout = 300;
                session->data->flags |= FLAG_REPLIED;
            }

            new_addr = session->data->in_addr;
            new_port = session->data->in_port;
            rcu_read_unlock_bh();
        } else {
            rcu_read_unlock_bh();
            atomic64_inc(&dnat_dropped);
            if (nat_log_verbose && in6_addr_in_pool6_range(&ip6h->daddr) && l4proto != IPPROTO_ICMPV6)
                printk(KERN_DEBUG "xt_NAT IPv6 DNAT: no session for proto=%u %pI6:%u\n",
                       (unsigned int)l4proto, &ip6h->daddr, ntohs(dst_port));
            return NF_ACCEPT;
        }

        if (l4proto == IPPROTO_TCP && tcp) {
            inet_proto_csum_replace16(&tcp->check, skb, (__be32 *)&ip6h->daddr, (__be32 *)&new_addr, true);
            inet_proto_csum_replace2(&tcp->check, skb, tcp->dest, new_port, true);
            ip6h->daddr = new_addr;
            tcp->dest = new_port;
        } else if (l4proto == IPPROTO_UDP && udp) {
            if (udp->check) {
                inet_proto_csum_replace16(&udp->check, skb, (__be32 *)&ip6h->daddr, (__be32 *)&new_addr, true);
                inet_proto_csum_replace2(&udp->check, skb, udp->dest, new_port, true);
            }
            ip6h->daddr = new_addr;
            udp->dest = new_port;
        } else if (l4proto == IPPROTO_ICMPV6 && icmp6) {
            inet_proto_csum_replace16(&icmp6->icmp6_cksum, skb, (__be32 *)&ip6h->daddr, (__be32 *)&new_addr, true);
            ip6h->daddr = new_addr;
            if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST || icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
                inet_proto_csum_replace2(&icmp6->icmp6_cksum, skb, icmp6->icmp6_identifier, new_port, true);
                icmp6->icmp6_identifier = new_port;
            }
        } else {
            ip6h->daddr = new_addr;
        }
    }

    return NF_ACCEPT;
}

/*
 * 定时清理：每轮处理 1/10 的哈希桶。IPv4：inner/outer 表项 timeout 减 10，≤-10 则删除并 dec(sessions_active)；
 * IPv6：ht6_inner/ht6_outer 中 timeout≤-10 的删除并 dec(sessions_active)。每 100ms 触发一次。
 *
 * P2-2 优化：sessions_timer_lock 仅保护向量计算和定时器重调度，
 * 释放后再做实际的 per-bucket 清理，大幅减少持锁时间。
 */
static void sessions_cleanup_timer_callback(struct timer_list *timer)
{
    struct nat_htable_ent *session;
    struct hlist_head *head;
    struct hlist_node *next;
    unsigned int i;
    struct nat_session *p;
    u_int32_t v4_start = 0, v4_end = 0;
    u_int32_t v6_start = 0, v6_end = 0;
    bool do_v4, do_v6;

    (void)timer;

    spin_lock_bh(&sessions_timer_lock);

    if (READ_ONCE(nat_exiting)) {
        spin_unlock_bh(&sessions_timer_lock);
        return;
    }

#define CLEANUP_SEGMENTS 10

    /* 仅在锁内计算本轮清理的桶范围 */
    do_v4 = (ht_inner && ht_outer);
    if (do_v4) {
        u_int32_t chunk = nat_hash_size / CLEANUP_SEGMENTS;
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
        if (v4_start >= nat_hash_size) {
            v4_start = 0;
            v4_end = chunk;
            nat_htable_vector = 0;
        }
        if (v4_end > nat_hash_size)
            v4_end = nat_hash_size;
    }

    do_v6 = (ht6_inner && ht6_outer);
    if (do_v6) {
        u_int32_t v6_chunk = nat6_hash_size / CLEANUP_SEGMENTS;
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
        if (v6_start >= nat6_hash_size) {
            v6_start = 0;
            v6_end = v6_chunk;
            nat6_htable_vector = 0;
        }
        if (v6_end > nat6_hash_size)
            v6_end = nat6_hash_size;
    }

    /* P2-2: 先重调度再释放锁，缩短 sessions_timer_lock 持有时间 */
    mod_timer(&sessions_cleanup_timer, jiffies + msecs_to_jiffies(100));
    spin_unlock_bh(&sessions_timer_lock);

    /* ---- 以下清理工作不持有 sessions_timer_lock ---- */

    if (do_v4) {
        for (i = v4_start; i < v4_end; i++) {
            spin_lock_bh(&ht_inner[i].lock);
            if (ht_inner[i].use > 0) {
                head = &ht_inner[i].session;
                hlist_for_each_entry_safe(session, next, head, list_node) {
                    session->data->timeout -= 10;
                    if (session->data->timeout == 0) {
                        netflow_export_flow_v5(session->proto, session->addr, session->port, session->data->out_addr, session->data->out_port, 1);
                    } else if (session->data->timeout <= -10) {
                        hlist_del_rcu(&session->list_node);
                        ht_inner[i].use--;
                        call_rcu(&session->rcu, nat_ent_rcu_free);
                    }
                }
            }
            spin_unlock_bh(&ht_inner[i].lock);
        }

        for (i = v4_start; i < v4_end; i++) {
            spin_lock_bh(&ht_outer[i].lock);
            if (ht_outer[i].use > 0) {
                head = &ht_outer[i].session;
                hlist_for_each_entry_safe(session, next, head, list_node) {
                    if (session->data->timeout <= -10) {
                        hlist_del_rcu(&session->list_node);
                        ht_outer[i].use--;
                        /* P0-1: 释放端口 bitmap 位 */
                        {
                            unsigned int aid = ntohl(session->addr) - ntohl(nat_pool_start);
                            unsigned long *bm = get_port_bitmap(aid, session->proto);
                            if (bm)
                                clear_bit(ntohs(session->port), bm);
                        }
                        p = session->data;
                        call_rcu(&session->rcu, nat_ent_rcu_free);
                        kmem_cache_free(nat_session_cachep, p);
                        atomic64_dec(&sessions_active);
                    }
                }
            }
            spin_unlock_bh(&ht_outer[i].lock);
        }
    }

    if (do_v6) {
        struct nat6_htable_ent *ent6;
        struct hlist_node *next6;
        struct hlist_head *head6;
        struct nat6_session_data *p6;

        for (i = v6_start; i < v6_end; i++) {
            spin_lock_bh(&ht6_inner[i].lock);
            if (ht6_inner[i].use > 0) {
                head6 = &ht6_inner[i].session;
                hlist_for_each_entry_safe(ent6, next6, head6, list_node) {
                    ent6->data->timeout -= 10;
                    if (ent6->data->timeout <= -10) {
                        hlist_del_rcu(&ent6->list_node);
                        ht6_inner[i].use--;
                        call_rcu(&ent6->rcu, nat6_ent_rcu_free);
                    }
                }
            }
            spin_unlock_bh(&ht6_inner[i].lock);
        }

        for (i = v6_start; i < v6_end; i++) {
            spin_lock_bh(&ht6_outer[i].lock);
            if (ht6_outer[i].use > 0) {
                head6 = &ht6_outer[i].session;
                hlist_for_each_entry_safe(ent6, next6, head6, list_node) {
                    if (ent6->data->timeout <= -10) {
                        hlist_del_rcu(&ent6->list_node);
                        ht6_outer[i].use--;
                        /* P0-2: 同时从辅助索引移除 */
                        if (ht6_outer_by_addr) {
                            unsigned int ah = get_hash_nat6_addr(ent6->proto, &ent6->addr);
                            spin_lock_bh(&ht6_outer_by_addr[ah].lock);
                            hlist_del_rcu(&ent6->addr_list_node);
                            ht6_outer_by_addr[ah].use--;
                            spin_unlock_bh(&ht6_outer_by_addr[ah].lock);
                        }
                        p6 = ent6->data;
                        call_rcu(&ent6->rcu, nat6_ent_rcu_free);
                        kmem_cache_free(nat6_session_data_cachep, p6);
                        atomic64_dec(&sessions_active);
                    }
                }
            }
            spin_unlock_bh(&ht6_outer[i].lock);
        }
    }
}

static void nf_send_timer_callback(struct timer_list *timer)
{
    (void)timer;
    if (READ_ONCE(nat_exiting))
        return;
    spin_lock_bh(&nfsend_lock);
    netflow_export_pdu_v5();
    mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&nfsend_lock);
}

/* /proc/net/NAT/statistics：会话与丢包等计数（IPv4+IPv6 共用 sessions_active） */
static int stat_seq_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Active NAT sessions: %lld\n", (long long)atomic64_read(&sessions_active));
    seq_printf(m, "Tried NAT sessions: %lld\n", (long long)atomic64_read(&sessions_tried));
    seq_printf(m, "Created NAT sessions: %lld\n", (long long)atomic64_read(&sessions_created));
    seq_printf(m, "DNAT dropped pkts: %lld\n", (long long)atomic64_read(&dnat_dropped));
    seq_printf(m, "Fragmented pkts: %lld\n", (long long)atomic64_read(&frags));
    seq_printf(m, "Related ICMP pkts: %lld\n", (long long)atomic64_read(&related_icmp));

    return 0;
}
static int stat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, stat_seq_show, NULL);
}
static const XT_NAT_PROC_OPS stat_seq_fops = {
    XT_NAT_PROC_OPEN           = stat_seq_open,
    XT_NAT_PROC_READ           = seq_read,
    XT_NAT_PROC_LSEEK          = seq_lseek,
    XT_NAT_PROC_RELEASE        = single_release,
};

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

        /* skip initial separators */
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

        if (!(usock = vmalloc(sizeof(*usock)))) {
            printk(KERN_ERR "xt_NAT: can't vmalloc socket\n");
            return -ENOMEM;
        }
        memset(usock, 0, sizeof(*usock));
        usock->addr = ss;
        list_add_tail(&usock->list, &usock_list);
        printk(KERN_INFO "xt_NAT NEL: add destination %s\n", print_sockaddr(&usock->addr));
    }
    return 0;
}

/* IPv4 NAT target：仅挂 FORWARD/PRE_ROUTING/POST_ROUTING，不挂 LOCAL_OUT（本机出口走 POST_ROUTING） */
static struct xt_target nat_tg_reg __read_mostly = {
    .name     = "NAT",
    .revision = 0,
    .family   = NFPROTO_IPV4,
    .hooks    = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING),
    .target   = nat_tg,
    .targetsize = sizeof(struct xt_nat_tginfo),
    .me       = THIS_MODULE,
};

/* IPv6 NAT target：同上，本机发出的包在 POST_ROUTING 命中 SNAT 规则 */
static struct xt_target nat_tg6_reg __read_mostly = {
    .name     = "NAT",
    .revision = 0,
    .family   = NFPROTO_IPV6,
    .hooks    = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING),
    .target   = nat_tg6,
    .targetsize = sizeof(struct xt_nat_tginfo),
    .me       = THIS_MODULE,
};

/* 模块初始化：解析 nat_pool/nat_pool6，建哈希表与定时器，注册 IPv4/IPv6 NAT target */
static int __init nat_tg_init(void)
{
    char buff[128] = { 0 };
    int ret;
    int i, j;

    printk(KERN_INFO "Module xt_NAT loaded\n");

    for(i=0, j=0; i<128 && nat_pool[i] != '-' && nat_pool[i] != '\0'; i++, j++) {
        buff[j] = nat_pool[i];
    }
    nat_pool_start = in_aton(buff);

    for(i++, j=0; i<128 && nat_pool[i] != '-' && nat_pool[i] != '\0'; i++, j++) {
        buff[j] = nat_pool[i];
    }
    nat_pool_end = in_aton(buff);

    if (nat_pool_start && nat_pool_end && nat_pool_start <= nat_pool_end ) {
        printk(KERN_INFO "xt_NAT DEBUG: IP Pool from %pI4 to %pI4\n", &nat_pool_start, &nat_pool_end);
    } else {
        printk(KERN_INFO "xt_NAT DEBUG: BAD IP Pool from %pI4 to %pI4\n", &nat_pool_start, &nat_pool_end);
        return -1;
    }

    if (parse_nat_pool6() == 0) {
        /* 直接打印用户传入的字符串，与 test.sh/命令行一致（%pI6 会显示 00a1 等前导零，易与 a1 混淆） */
        printk(KERN_INFO "xt_NAT DEBUG: IPv6 Pool %s\n", nat_pool6);
    } else {
        printk(KERN_INFO "xt_NAT DEBUG: BAD IPv6 Pool: %s\n", nat_pool6);
        return -1;
    }

    printk(KERN_INFO "xt_NAT DEBUG: NAT hash size: %d\n", nat_hash_size);

    /* P3-1: 创建专用 slab cache */
    nat_session_cachep = kmem_cache_create("xt_nat_session",
                          sizeof(struct nat_session), 0, SLAB_HWCACHE_ALIGN, NULL);
    nat_htable_ent_cachep = kmem_cache_create("xt_nat_htable_ent",
                          sizeof(struct nat_htable_ent), 0, SLAB_HWCACHE_ALIGN, NULL);
    nat6_session_data_cachep = kmem_cache_create("xt_nat6_session_data",
                          sizeof(struct nat6_session_data), 0, SLAB_HWCACHE_ALIGN, NULL);
    nat6_htable_ent_cachep = kmem_cache_create("xt_nat6_htable_ent",
                          sizeof(struct nat6_htable_ent), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!nat_session_cachep || !nat_htable_ent_cachep ||
        !nat6_session_data_cachep || !nat6_htable_ent_cachep) {
        printk(KERN_ERR "xt_NAT: failed to create slab caches\n");
        if (nat6_htable_ent_cachep)   kmem_cache_destroy(nat6_htable_ent_cachep);
        if (nat6_session_data_cachep) kmem_cache_destroy(nat6_session_data_cachep);
        if (nat_htable_ent_cachep)    kmem_cache_destroy(nat_htable_ent_cachep);
        if (nat_session_cachep)       kmem_cache_destroy(nat_session_cachep);
        return -ENOMEM;
    }

    nat_htable_create();
    nat6_htable_create();
    pool_table_create();

    /* P1-2: 初始化 IPv6 create_session 哈希锁 */
    for (i = 0; i < NAT6_CREATE_LOCK_SIZE; i++)
        spin_lock_init(&create_session6_lock[i]);

    add_nf_destinations(nf_dest);

    proc_net_nat = proc_mkdir("NAT",init_net.proc_net);
    proc_create("statistics", 0644, proc_net_nat, &stat_seq_fops);

    spin_lock_bh(&sessions_timer_lock);
    timer_setup(&sessions_cleanup_timer, sessions_cleanup_timer_callback, 0);
    mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&sessions_timer_lock);

    spin_lock_bh(&nfsend_lock);
    timer_setup(&nf_send_timer, nf_send_timer_callback, 0);
    mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&nfsend_lock);

    ret = xt_register_target(&nat_tg_reg);
    if (ret)
        return ret;

    ret = xt_register_target(&nat_tg6_reg);
    if (ret) {
        xt_unregister_target(&nat_tg_reg);
        return ret;
    }

    return 0;
}

static void __exit nat_tg_exit(void)
{
    /* 1) 注销 target，确保不会有新包进入 nat_tg / nat_tg6 */
    xt_unregister_target(&nat_tg6_reg);
    xt_unregister_target(&nat_tg_reg);

    /* 2) 设置退出标志，让定时器回调不再自重启（mod_timer） */
    WRITE_ONCE(nat_exiting, true);

    /* 3) 等待正在执行的定时器回调完成；因 nat_exiting=true，回调不会再 mod_timer */
    del_timer_sync(&sessions_cleanup_timer);
    del_timer_sync(&nf_send_timer);

    /* 4) 移除 proc */
    remove_proc_entry( "statistics", proc_net_nat );
    proc_remove(proc_net_nat);

    /* 5) 等待所有 RCU 读端和 call_rcu 回调完成 */
    synchronize_rcu();
    rcu_barrier();

    /* 6) 此时无并发访问，安全清理所有资源 */
    pool_table_remove();
    nat_htable_remove();
    nat6_htable_remove();

    while (!list_empty(&usock_list)) {
        struct netflow_sock *usock;

        usock = list_entry(usock_list.next, struct netflow_sock, list);
        list_del(&usock->list);
        if (usock->sock)
            sock_release(usock->sock);
        usock->sock = NULL;
        vfree(usock);
    }

    /* P3-1: 销毁专用 slab cache */
    kmem_cache_destroy(nat6_htable_ent_cachep);
    kmem_cache_destroy(nat6_session_data_cachep);
    kmem_cache_destroy(nat_htable_ent_cachep);
    kmem_cache_destroy(nat_session_cachep);

    printk(KERN_INFO "Module xt_NAT unloaded\n");
}

module_init(nat_tg_init);
module_exit(nat_tg_exit);

MODULE_DESCRIPTION("Xtables: Full Cone NAT");
MODULE_AUTHOR("Andrei Sharaev <andr.sharaev@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_NAT");
MODULE_ALIAS("ip6t_NAT");
