#include "hackernel/net.h"
#include "hknl/netlink.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

namespace hackernel {

// 在这里面构造netlink协议包,发送到内核
static int NetProtectStatusUpdate(uint8_t status) {
    struct nl_msg *message;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_NET_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_u8(message, NET_A_OP_TYPE, status);
    nl_send_auto(NetlinkGetNlSock(), message);

    return 0;
}

int NetPolicyInsert(const NetPolicy *policy) {
    struct nl_msg *message;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_NET_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_u8(message, NET_A_OP_TYPE, NET_PROTECT_INSERT);

    nla_put_s32(message, NET_A_ID, policy->id);
    nla_put_s8(message, NET_A_PRIORITY, policy->priority);

    nla_put_u32(message, NET_A_ADDR_SRC_BEGIN, policy->addr.src.begin);
    nla_put_u32(message, NET_A_ADDR_SRC_END, policy->addr.src.end);
    nla_put_u32(message, NET_A_ADDR_DST_BEGIN, policy->addr.dst.begin);
    nla_put_u32(message, NET_A_ADDR_DST_END, policy->addr.dst.end);

    nla_put_u16(message, NET_A_PORT_SRC_BEGIN, policy->port.src.begin);
    nla_put_u16(message, NET_A_PORT_SRC_END, policy->port.src.end);
    nla_put_u16(message, NET_A_PORT_DST_BEGIN, policy->port.dst.begin);
    nla_put_u16(message, NET_A_PORT_DST_END, policy->port.dst.end);

    nla_put_u8(message, NET_A_PROTOCOL_BEGIN, policy->protocol.begin);
    nla_put_u8(message, NET_A_PROTOCOL_END, policy->protocol.end);

    nla_put_u32(message, NET_A_RESPONSE, policy->response);
    nla_put_s32(message, NET_A_FLAGS, policy->flags);

    nl_send_auto(NetlinkGetNlSock(), message);

    return 0;
}
int NetPolicyDelete(NetPolicyId id) {
    struct nl_msg *message;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_NET_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_u8(message, NET_A_OP_TYPE, NET_PROTECT_DELETE);
    nla_put_u32(message, NET_A_ID, id);
    nl_send_auto(NetlinkGetNlSock(), message);

    return 0;
}

int NetProtectEnable() {
    return NetProtectStatusUpdate(NET_PROTECT_ENABLE);
}
int NetProtectDisable() {
    return NetProtectStatusUpdate(NET_PROTECT_DISABLE);
}

};  // namespace hackernel
