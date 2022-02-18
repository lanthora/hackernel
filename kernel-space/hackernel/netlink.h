/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_NETLINK_H
#define HACKERNEL_NETLINK_H

#include <linux/skbuff.h>
#include <net/genetlink.h>

#define HACKERNEL_FAMLY_NAME "HACKERNEL"
#define HACKERNEL_FAMLY_VERSION 1

enum {
	HACKERNEL_C_UNSPEC,
	HACKERNEL_C_HANDSHAKE,
	HACKERNEL_C_PROCESS_PROTECT,
	HACKERNEL_C_FILE_PROTECT,
	HACKERNEL_C_NET_PROTECT,
	__HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

void netlink_kernel_start(void);
void netlink_kernel_stop(void);

extern u32 hackernel_portid;
extern struct net *hackernel_net;

int handshake_handler(struct sk_buff *skb, struct genl_info *info);

#endif
