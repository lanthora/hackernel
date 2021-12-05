#ifndef HACKERNEL_NET_H
#define HACKERNEL_NET_H

#include "util.h"
#include <netlink/genl/mngt.h>

EXTERN_C_BEGIN

typedef uint32_t NetAddr;
typedef uint16_t NetPort;
typedef uint8_t NetProtocol;
typedef uint32_t NetResponse;
typedef uint32_t NetPolicyId;
typedef int8_t NetPriority;

#define NET_POLICY_DROP 0
#define NET_POLICY_ACCEPT 1

enum {
    NET_PROTECT_UNSPEC,
    NET_PROTECT_ENABLE,
    NET_PROTECT_DISABLE,
    NET_PROTECT_INSERT,
    NET_PROTECT_DELETE,
};

int NetProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg);

// 优先级(Priority)相同的情况下, 后添加的优先命中,多个NetPolicy可以有相同的id,
// 根据Id可以批量删除 所有的数据都为主机序
struct NetPolicy {
    NetPolicyId id;
    NetPriority priority;

    struct {
        struct {
            NetAddr begin;
            NetAddr end;
        } src;
        struct {
            NetAddr begin;
            NetAddr end;
        } dst;
    } addr;

    struct {
        struct {
            NetPort begin;
            NetPort end;
        } src;
        struct {
            NetPort begin;
            NetPort end;
        } dst;
    } port;

    struct {
        NetProtocol begin;
        NetProtocol end;
    } protocol;

    NetResponse response;
    int flags;
};

int NetPolicyInsert(const struct NetPolicy *policy);
int NetPolicyDelete(NetPolicyId id);

int NetProtectEnable(void);
int NetProtectDisable(void);

enum {
    NET_A_UNSPEC,
    NET_A_SESSION,

    NET_A_STATUS_CODE,
    NET_A_OP_TYPE,
    NET_A_ID,
    NET_A_PRIORITY,
    NET_A_ADDR_SRC_BEGIN,
    NET_A_ADDR_SRC_END,
    NET_A_ADDR_DST_BEGIN,
    NET_A_ADDR_DST_END,
    NET_A_PORT_SRC_BEGIN,
    NET_A_PORT_SRC_END,
    NET_A_PORT_DST_BEGIN,
    NET_A_PORT_DST_END,
    NET_A_PROTOCOL_BEGIN,
    NET_A_PROTOCOL_END,
    NET_A_RESPONSE,
    NET_A_FLAGS,

    __NET_A_MAX,
};
#define NET_A_MAX (__NET_A_MAX - 1)

#define FLAG_NET_INBOUND (1U << 0)
#define FLAG_NET_OUTBOUND (1U << 1)
#define FLAG_NET_ONLY_CHECK_NEW_TCP (1U << 2)
#define FLAG_NET_ONLY_ALLOW_TCP_HEADER (1U << 3)

EXTERN_C_END

#endif
