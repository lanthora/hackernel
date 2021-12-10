#ifndef HACKERNEL_KEEPALIVE_H
#define HACKERNEL_KEEPALIVE_H

#include "hackernel/util.h"
#include "heartbeat/define.h"
#include <netlink/genl/mngt.h>

namespace hackernel {

int HeartbeatHandler(struct nl_cache_ops* unused, struct genl_cmd* genl_cmd, struct genl_info* genl_info, void* arg);
int HeartbeatStart(void);
void HeartbeatStop(void);
int Handshake(void);

};  // namespace hackernel

#endif
