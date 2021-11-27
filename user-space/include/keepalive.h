#ifndef HACKERNEL_KEEPALIVE_H
#define HACKERNEL_KEEPALIVE_H

#include "util.h"
#include <netlink/genl/mngt.h>

EXTERN_C_BEGIN

enum {
    HANDSHAKE_A_UNSPEC,
    HANDSHAKE_A_STATUS_CODE,
    HANDSHAKE_A_SYS_SERVICE_TGID,
    __HANDSHAKE_A_MAX,
};
#define HANDSHAKE_A_MAX (__HANDSHAKE_A_MAX - 1)

int KeepAliveHandler(struct nl_cache_ops* unused, struct genl_cmd* genl_cmd, struct genl_info* genl_info, void* arg);

int HeartbeatStart(void);
void HeartbeatStop(void);

EXTERN_C_END

#endif
