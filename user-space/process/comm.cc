/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/process.h"
#include "nlc/netlink.h"
#include "process/protector.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

int update_process_protection_status(int32_t session, uint8_t status) {
    struct nl_msg *message = NULL;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_PROCESS_PROTECT);

    nla_put_s32(message, PROCESS_A_SESSION, session);
    nla_put_u8(message, PROCESS_A_OP_TYPE, status);

    send_free_hackernel_nlmsg(message);
    return 0;
}

int enable_process_protection(int32_t session) {
    return update_process_protection_status(session, PROCESS_PROTECT_ENABLE);
}
int disable_process_protection(int32_t session) {
    return update_process_protection_status(session, PROCESS_PROTECT_DISABLE);
}

proc_perm check_process_permission(char *cmd) {
    auto &auditor = process_protector::global();
    return auditor.handle_new_cmd(cmd);
}

int reply_process_permission(proc_perm_id id, proc_perm perm) {
    struct nl_msg *message = NULL;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_PROCESS_PROTECT);
    nla_put_u8(message, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
    nla_put_s32(message, PROCESS_A_ID, id);
    nla_put_s32(message, PROCESS_A_PERM, perm);
    send_free_hackernel_nlmsg(message);
    return 0;
}

static int generate_process_protection_report_msg(const std::string &cmd, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::proc::report";
    doc["cmd"] = cmd;
    msg = generate_system_broadcast_msg(doc);
    return 0;
}

static int generate_process_protection_enable_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::proc::enable";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_process_protection_disable_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::proc::disable";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

int handle_genl_process_protection(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                                   void *arg) {
    u_int8_t type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
    int error, id, code, session;
    char *name;
    std::string msg;

    switch (type) {
    case PROCESS_PROTECT_ENABLE:
        session = nla_get_s32(genl_info->attrs[PROCESS_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
        generate_process_protection_enable_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::proc::enable, session=[%d] code=[%d]", session, code);
        break;

    case PROCESS_PROTECT_DISABLE:
        session = nla_get_s32(genl_info->attrs[PROCESS_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
        generate_process_protection_disable_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::proc::disable, session=[%d] code=[%d]", session, code);
        break;

    case PROCESS_PROTECT_REPORT:
        id = nla_get_s32(genl_info->attrs[PROCESS_A_ID]);
        name = nla_get_string(genl_info->attrs[PROCESS_A_NAME]);
        DBG("kernel::proc::report, id=[%d] name=[%s]", id, name);

        generate_process_protection_report_msg(name, msg);
        broadcaster::global().broadcast(msg);

        error = reply_process_permission(id, check_process_permission(name));
        if (error)
            WARN("reply_process_permission failed, id=[%d] name=[%s]", id, name);

        break;

    default:
        DBG("Unknown process protect command Type");
    }
    return 0;
}

}; // namespace hackernel
