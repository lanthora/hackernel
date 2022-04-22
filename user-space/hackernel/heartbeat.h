/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_KEEPALIVE_H
#define HACKERNEL_KEEPALIVE_H

#include "hackernel/util.h"
#include "heartbeat/define.h"
#include <netlink/genl/mngt.h>

namespace hackernel {

int handle_heartbeat(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg);
int start_heartbeat(void);
void stop_heartbeat(void);
int handshake_with_kernel(void);

}; // namespace hackernel

#endif
