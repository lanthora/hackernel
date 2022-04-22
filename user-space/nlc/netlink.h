/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HKNL_NETLINK_H
#define HKNL_NETLINK_H

#include "hackernel/util.h"
#include <netlink/msg.h>
#include <stdint.h>

EXTERN_C_BEGIN

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

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

void init_netlink_server(void);
int start_netlink(void);
int stop_netlink(void);

struct nl_msg *alloc_hackernel_nlmsg(uint8_t cmd);
int send_free_hackernel_nlmsg(struct nl_msg *message);

EXTERN_C_END

#endif
