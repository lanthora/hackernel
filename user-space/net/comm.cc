#include "hackernel/broadcaster.h"
#include "hackernel/net.h"
#include "hknl/netlink.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

// 在这里面构造netlink协议包,发送到内核
static int NetProtectStatusUpdate(int32_t session, uint8_t status) {
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

int NetProtectEnable(int32_t session) {
    return NetProtectStatusUpdate(session, NET_PROTECT_ENABLE);
}
int NetProtectDisable(int32_t session) {
    return NetProtectStatusUpdate(session, NET_PROTECT_DISABLE);
}

int NetProtectEnable() {
    return NetProtectEnable(0);
}
int NetProtectDisable() {
    return NetProtectDisable(0);
}

int NetEnableJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::enable";
    doc["session"] = session;
    doc["code"] = code;
    msg = doc.dump();
    return 0;
}

int NetDisableJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::disable";
    doc["session"] = session;
    doc["code"] = code;
    msg = doc.dump();
    return 0;
}

int NetInsertJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::insert";
    doc["session"] = session;
    doc["code"] = code;
    msg = doc.dump();
    return 0;
}

int NetDeleteJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::delete";
    doc["session"] = session;
    doc["code"] = code;
    msg = doc.dump();
    return 0;
}

int NetProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;
    int code;
    int32_t session;
    std::string msg;

    type = nla_get_u8(genl_info->attrs[NET_A_OP_TYPE]);
    switch (type) {
    case NET_PROTECT_ENABLE:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        NetEnableJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        LOG("kernel::net::enable, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_DISABLE:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        NetDisableJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        LOG("kernel::net::disable, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_INSERT:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        NetInsertJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        LOG("kernel::net::insert, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_DELETE:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        NetDeleteJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        LOG("kernel::net::delete, session=[%d] code=[%d]", session, code);
        break;

    default:
        LOG("Unknown net protect command Type");
    }
    return 0;
}

}; // namespace hackernel
