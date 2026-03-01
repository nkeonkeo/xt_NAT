/* This code is derived from the Linux Kernel sources intended
 * to maintain compatibility with different Kernel versions.
 * Copyright of original source is of respective Linux Kernel authors.
 * License is GPLv2.
 */

#ifndef COMPAT_NAT_H
#define COMPAT_NAT_H

#include <net/checksum.h>
#ifndef CSUM_MANGLED_0
/* UDP checksum of 0 means "no checksum" in IPv4; use 0xFFFF when we mangle to 0 */
#define CSUM_MANGLED_0 ((__force __sum16)0xFFFF)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
# define sock_create_kern(f, t, p, s) sock_create_kern(&init_net, f, t, p, s)
#endif

#endif /* COMPAT_NAT_H */

