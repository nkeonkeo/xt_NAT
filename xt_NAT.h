#ifndef _LINUX_NETFILTER_XT_NAT_H
#define _LINUX_NETFILTER_XT_NAT_H 1

enum xt_nat_target_variant {
    XTNAT_SNAT,
    XTNAT_DNAT,
};

struct xt_nat_tginfo {
    uint8_t variant;
};

/* ---- Netflow v9 (RFC 3954) ---- */

#define NF9_VERSION		9

#define NF9_FLOWSET_TEMPLATE	0
#define NF9_FLOWSET_OPTIONS	1

#define NF9_TMPL_ID_NAT4	256
#define NF9_TMPL_ID_NAT6	257

#define NF9_V4_MAX		30
#define NF9_V6_MAX		20
#define NF9_TMPL_INTERVAL	20

/* field type IDs (RFC 3954 / IANA) */
#define NF9_IN_BYTES		1
#define NF9_IN_PKTS		2
#define NF9_PROTOCOL		4
#define NF9_TCP_FLAGS		6
#define NF9_L4_SRC_PORT	7
#define NF9_IPV4_SRC_ADDR	8
#define NF9_L4_DST_PORT	11
#define NF9_IPV4_DST_ADDR	12
#define NF9_LAST_SWITCHED	21
#define NF9_FIRST_SWITCHED	22
#define NF9_IPV6_SRC_ADDR	27
#define NF9_IPV6_DST_ADDR	28

#define NF9_NAT4_FIELD_COUNT	8
#define NF9_NAT6_FIELD_COUNT	8

struct nf9_header {
    __be16	version;
    __be16	count;
    __be32	sys_uptime;
    __be32	unix_secs;
    __be32	sequence;
    __be32	source_id;
} __attribute__((packed));

struct nf9_flowset_header {
    __be16	flowset_id;
    __be16	length;
} __attribute__((packed));

struct nf9_template_field {
    __be16	field_type;
    __be16	field_length;
} __attribute__((packed));

struct nf9_nat4_record {
    __be32	src_addr;
    __be16	src_port;
    __be32	dst_addr;
    __be16	dst_port;
    __u8	protocol;
    __u8	tcp_flags;
    __be32	first_switched;
    __be32	last_switched;
} __attribute__((packed));

struct nf9_nat6_record {
    __u8	src_addr[16];
    __be16	src_port;
    __u8	dst_addr[16];
    __be16	dst_port;
    __u8	protocol;
    __u8	tcp_flags;
    __be32	first_switched;
    __be32	last_switched;
} __attribute__((packed));

#endif /* _LINUX_NETFILTER_XT_NAT_H */

