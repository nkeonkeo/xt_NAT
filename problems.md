Sessions 超过 1 万后的性能问题分析
1. [严重] search_free_l4_port() / search_free_l4_port6() — O(N) 线性端口搜索
xt_NAT.c
Lines 570-587

static uint16_t search_free_l4_port(const uint8_t proto, const u_int32_t nataddr, const uint16_t userport)
{
    uint16_t i, freeport;
    for(i = 0; i < 64512; i++) {
        freeport = ntohs(userport) + i;
 
        if (freeport < 1024) {
            freeport += 1024;
        }
 
        //printk(KERN_DEBUG "xt_NAT search_free_l4_port: check nat port = %d\n", freeport);
 
        if(!lookup_session(ht_outer, proto, nataddr, htons(freeport))) {
            return htons(freeport);
        }
    }
    return 0;
}
问题：每次新建会话都需要找一个空闲端口。当一个 NAT IP 上已经积累了大量会话时，此函数需要反复调用 lookup_session() 来逐个检查端口是否被占用。

假设 NAT 池只有 1 个 IP，10000 个会话，最坏情况下需要调用 lookup_session() 10000 次才能找到空闲端口
该函数在 create_nat_session() 中调用，而 create_nat_session() 持有 create_session_lock[nataddr_id] 自旋锁，长时间搜索会阻塞该 NAT IP 上的所有并发会话创建
IPv6 版本 search_free_l4_port6() 有同样的问题
建议：使用 bitmap 跟踪每个 NAT IP 的端口占用状态，将端口分配从 O(N) 降为 O(1)；或使用随机起始偏移减少冲突概率。

2. [严重] lookup_nat6_outer_by_addr() — 全表线性扫描
xt_NAT.c
Lines 873-890

static struct nat6_htable_ent *lookup_nat6_outer_by_addr(const uint8_t proto, const struct in6_addr *addr)
{
    struct nat6_htable_ent *ent;
    struct hlist_head *head;
    unsigned int i;
 
    for (i = 0; i < nat6_hash_size; i++) {
        if (ht6_outer[i].use == 0)
            continue;
        head = &ht6_outer[i].session;
        hlist_for_each_entry_rcu(ent, head, list_node) {
            if (ent->proto == proto && ent->data->timeout > 0 &&
                ipv6_addr_equal(&ent->addr, addr))
                return ent;
        }
    }
    return NULL;
}
问题：此函数遍历整个 ht6_outer 哈希表（64K 个桶 + 所有链表节点），时间复杂度为 O(nat6_hash_size + sessions)。

该函数在每个 ICMPv6 非 ECHO 的 DNAT 包路径上被调用（第 1737-1738 行）
当有 1 万个 IPv6 会话时，需要遍历 64K 个桶外加可能访问 1 万个链表节点
这是在数据面（packet path）上的全表扫描，严重影响延迟
建议：为 (proto, addr) 建立一个独立的辅助哈希索引，避免全表扫描。

3. [中等] use 字段类型为 uint8_t — 桶内计数器溢出风险
xt_NAT.c
Lines 110-114

struct xt_nat_htable {
    uint8_t use;
    spinlock_t lock;
    struct hlist_head session;
};
问题：use 是 uint8_t，最大值为 255。如果哈希冲突导致某个桶内积累超过 255 个会话，use 会回绕到 0。

lookup_session() 第 555 行有 if (ht[hash].use == 0) return NULL; 的快速路径判断
一旦 use 溢出回绕到 0，该桶内的所有会话都将无法被查找到（lookup 直接返回 NULL），导致重复创建会话、端口泄漏、内存泄漏
IPv4 有 1M 桶，1 万会话平均 0.01/桶，溢出不太可能；但如果 nat_hash_size 被配置得较小，或哈希分布不均，风险上升
IPv6 只有 64K 桶，1 万会话平均 ~0.15/桶，仍安全；但随着会话数增长到更高量级（如 10 万+），风险显著增加
建议：将 use 改为 uint32_t 或 uint16_t。

4. [中等] create_session_lock — 单 NAT IP 的序列化瓶颈
xt_NAT.c
Lines 95-96

static spinlock_t *create_session_lock;
xt_NAT.c
Lines 745-749

    for (attempt = 0; attempt < max_attempts; attempt++) {
        nataddr = get_random_nat_addr();
        nataddr_id = ntohl(nataddr) - ntohl(nat_pool_start);
        //printk(KERN_DEBUG "xt_NAT create_nat_session: nataddr_id = %u (%u - %u)\n", nataddr_id, ntohl(nataddr), ntohl(nat_pool_start));
        spin_lock_bh(&create_session_lock[nataddr_id]);
问题：create_session_lock 是 per-NAT-IP 的自旋锁。当 NAT 池较小（例如只有 1-2 个 IP）时：

所有会话创建都序列化在同一个锁上
锁内还要执行 search_free_l4_port()（前述 O(N) 操作），持锁时间随会话数线性增长
1 万会话 × 多核并发 → 严重的自旋锁争用和 CPU 浪费
建议：缩小临界区，将端口搜索移到锁外（先搜索候选端口，加锁后再验证）；或引入 per-IP 的无锁端口分配器。

5. [中等] 清理定时器持锁时间过长
xt_NAT.c
Lines 1810-1811

    spin_lock_bh(&sessions_timer_lock);
xt_NAT.c
Lines 1941-1942

    mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(100) );
    spin_unlock_bh(&sessions_timer_lock);
问题：sessions_cleanup_timer_callback() 持有 sessions_timer_lock 期间处理 1/10 的哈希桶。

IPv4 每轮处理 ~100K 个桶（1M/10），每个非空桶还要获取 ht_inner[i].lock / ht_outer[i].lock
当会话数增加到 1 万+，非空桶变多，每轮清理遍历的链表节点更多
内层锁 ht_inner[i].lock 和数据面的 lookup_session()/create_nat_session() 使用相同的锁，会互相阻塞
sessions_timer_lock 在 softirq（spin_lock_bh）上下文中持有，可能影响网络中断处理的延迟
另一个隐患：在清理 inner 表时递减 timeout（第 1846 行 session->data->timeout -= 10），然后在清理 outer 表时按 timeout <= -10 删除。这两个遍历之间存在时间窗口，数据面可能看到 timeout < 0 但 > -10 的会话，lookup_session() 的 timeout > 0 检查会过滤掉它们，这没问题——但该会话仍占用 outer 表中的一个槽位直到下一轮清理。

6. [中等] create_nat_session() 创建后再做一次 lookup
xt_NAT.c
Lines 842-843

        rcu_read_lock_bh();
        return lookup_session(ht_outer, proto, nataddr, natport);
问题：会话创建完成（已插入 inner/outer 表）后，不是直接返回已有的 session2 指针，而是重新在 outer 表中执行一次 lookup_session()。

这是一次不必要的哈希查找 + 链表遍历
IPv6 版本 create_nat6_session() 第 990 行同样如此
在高会话创建速率下，这些冗余查找累积成可观开销
建议：直接返回已创建的 session2 / ent_outer 指针。

7. [中等] IPv6 会话创建缺少 create_session_lock 保护
xt_NAT.c
Lines 912-993

static struct nat6_htable_ent *create_nat6_session(const uint8_t proto, const struct in6_addr *useraddr, const uint16_t userport)
{
    // ...
    for (attempt = 0; attempt < max_attempts; attempt++) {
        get_random_nat_addr6(&nataddr);
 
        rcu_read_lock_bh();
        ent_inner = lookup_nat6_session(ht6_inner, proto, useraddr, userport);
        // ... no create_session_lock acquired ...
问题：IPv4 的 create_nat_session() 使用 create_session_lock[nataddr_id] 来防止并发创建时的端口冲突，但 IPv6 版本 create_nat6_session() 完全没有类似的保护。

两个 CPU 可能同时为同一个 (proto, nataddr, port) 创建会话
search_free_l4_port6() 可能返回相同的空闲端口给两个并发调用者
这会导致 outer 表中同一个桶出现重复的 (proto, addr, port) 键，DNAT 查找会返回错误的会话
建议：为 IPv6 也引入类似的 per-NAT-IP 创建锁。

8. [低-中] GFP_ATOMIC 分配在高压下失败率上升
xt_NAT.c
Lines 774-775

        data_session = kzalloc(sz, GFP_ATOMIC);
xt_NAT.c
Lines 783-784

        session = kzalloc(sz, GFP_ATOMIC);
问题：每个会话需要 3 次 kzalloc(..., GFP_ATOMIC) 分配。GFP_ATOMIC 不能睡眠、不能回收页面，在内存压力大时失败率较高。

1 万会话 × 3 次分配 = 3 万个小对象散布在 slab 中
高速率创建/销毁会话导致 slab 碎片化
kfree_rcu 延迟释放会让内存在 RCU 宽限期内无法复用，峰值内存高于稳态
建议：使用 kmem_cache_create() 为 nat_session、nat_htable_ent、nat6_htable_ent 等创建专用 slab cache，提高分配效率和减少碎片。

9. [低-中] Netflow 导出在会话创建路径上的锁争用
xt_NAT.c
Lines 688-689

    spin_lock_bh(&nfsend_lock);
xt_NAT.c
Lines 837-837

        netflow_export_flow_v5(proto, useraddr, userport, nataddr, natport, 0);
问题：每次会话创建都会调用 netflow_export_flow_v5()，该函数获取全局 nfsend_lock。

1 万+会话的高创建速率意味着多核频繁争用 nfsend_lock
当 PDU 满 30 条记录时（第 720 行），还会在锁内执行 netflow_sendmsg() 进行网络 I/O
清理定时器删除会话时同样触发 netflow 导出（第 1848 行），与数据面争用同一把锁
10. [低] 哈希表内存开销不均衡
IPv4 ht_inner + ht_outer：每个 sizeof(struct xt_nat_htable) * 1M，约 24-32 MB（取决于 spinlock 和 hlist_head 大小），即使只有 1 万个会话
IPv6 ht6_inner + ht6_outer：每个 64K 桶，约 1-2 MB
当 session 数只有 1 万时，hash table 的负载因子极低（IPv4: 0.01, IPv6: 0.15），大量内存被浪费。但这不是性能问题本身，只是效率问题。

总结：按严重程度排序
优先级	问题	影响	触发条件
P0	search_free_l4_port O(N) 端口搜索	会话创建延迟线性增长，持锁时间增加	NAT 池小 + 会话数多
P0	lookup_nat6_outer_by_addr 全表扫描	每个 ICMPv6 DNAT 包的处理延迟为 O(64K+N)	IPv6 ICMPv6 非 ECHO 流量
P1	IPv6 无创建锁保护	并发条件下端口重复分配，会话表损坏	多核并发创建 IPv6 会话
P1	use 字段 uint8_t 溢出	桶内计数器溢出导致查找失败、会话泄漏	哈希冲突严重或哈希表较小
P2	create_session_lock 单IP序列化	多核争用，创建吞吐下降	NAT 池仅 1-2 个 IP
P2	清理定时器持锁过长	增加数据面延迟	会话数增多
P2	创建后冗余 lookup	不必要的 CPU 开销	每次会话创建
P3	GFP_ATOMIC 碎片化	内存压力下分配失败率升高	高速率创建销毁
P3	Netflow nfsend_lock 争用	创建路径额外延迟	启用 netflow + 高创建速率
