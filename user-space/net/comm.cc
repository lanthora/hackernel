/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "nlc/netlink.h"
#include <arpa/inet.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

static int update_net_protection_status(int32_t session, uint8_t status) {
    struct nl_msg *message;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_NET_PROTECT);
    nla_put_s32(message, NET_A_SESSION, session);
    nla_put_u8(message, NET_A_OP_TYPE, status);
    send_free_hackernel_nlmsg(message);

    return 0;
}

int enable_net_protection(int32_t session) {
    return update_net_protection_status(session, NET_PROTECT_ENABLE);
}

int disable_net_protection(int32_t session) {
    return update_net_protection_status(session, NET_PROTECT_DISABLE);
}

int insert_net_policy(int32_t session, const net_policy *policy) {
    struct nl_msg *message;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_NET_PROTECT);

    nla_put_s32(message, NET_A_SESSION, session);
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

    send_free_hackernel_nlmsg(message);

    return 0;
}

int delete_net_policy(int32_t session, net_policy_id id) {
    struct nl_msg *message;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_NET_PROTECT);
    nla_put_s32(message, NET_A_SESSION, session);
    nla_put_u8(message, NET_A_OP_TYPE, NET_PROTECT_DELETE);
    nla_put_u32(message, NET_A_ID, id);
    send_free_hackernel_nlmsg(message);

    return 0;
}

int clear_net_policy(int32_t session) {
    struct nl_msg *message;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_NET_PROTECT);
    nla_put_s32(message, NET_A_SESSION, session);
    nla_put_u8(message, NET_A_OP_TYPE, NET_PROTECT_CLEAR);
    send_free_hackernel_nlmsg(message);

    return 0;
}

static int generate_net_protection_enable_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::enable";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_net_protection_disable_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::disable";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_net_protection_insert_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::insert";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_net_protection_delete_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::delete";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_net_protection_clear_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::net::clear";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_net_protection_report_msg(uint8_t protocol, uint32_t saddr, uint32_t daddr, uint16_t sport,
                                              uint16_t dport, uint32_t policy, std::string &msg) {
    nlohmann::json doc;

    struct in_addr ip_addr;

    doc["type"] = "kernel::net::report";
    doc["protocol"] = protocol;
    ip_addr.s_addr = htonl(saddr);
    doc["saddr"] = inet_ntoa(ip_addr);
    ip_addr.s_addr = htonl(daddr);
    doc["daddr"] = inet_ntoa(ip_addr);
    doc["sport"] = sport;
    doc["dport"] = dport;
    doc["policy"] = policy;
    msg = generate_system_broadcast_msg(doc);
    return 0;
}

int handle_genl_net_protection(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                               void *arg) {
    u_int8_t type;
    int code;
    int32_t session;
    uint8_t protocol;
    uint32_t saddr, daddr;
    uint16_t sport, dport;
    uint32_t policy;
    std::string msg;

    type = nla_get_u8(genl_info->attrs[NET_A_OP_TYPE]);
    switch (type) {
    case NET_PROTECT_ENABLE:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        generate_net_protection_enable_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::net::enable, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_DISABLE:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        generate_net_protection_disable_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::net::disable, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_INSERT:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        generate_net_protection_insert_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::net::insert, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_DELETE:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        generate_net_protection_delete_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::net::delete, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_CLEAR:
        session = nla_get_s32(genl_info->attrs[NET_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        generate_net_protection_clear_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::net::clear, session=[%d] code=[%d]", session, code);
        break;

    case NET_PROTECT_REPORT:
        protocol = nla_get_u8(genl_info->attrs[NET_A_PROTOCOL_BEGIN]);
        saddr = nla_get_u32(genl_info->attrs[NET_A_ADDR_SRC_BEGIN]);
        daddr = nla_get_u32(genl_info->attrs[NET_A_ADDR_DST_BEGIN]);
        sport = nla_get_u16(genl_info->attrs[NET_A_PORT_SRC_BEGIN]);
        dport = nla_get_u16(genl_info->attrs[NET_A_PORT_DST_BEGIN]);
        policy = nla_get_u32(genl_info->attrs[NET_A_ID]);
        generate_net_protection_report_msg(protocol, saddr, daddr, sport, dport, policy, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::net::report, msg=[%s]", msg.data());
        break;

    default:
        DBG("Unknown net protect command Type");
    }
    return 0;
}

}; // namespace hackernel
