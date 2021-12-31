#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/process.h"
#include "hknl/netlink.h"
#include "process/audit.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

using namespace process;

int ProcProtectStatusUpdate(int32_t session, uint8_t status) {
    struct nl_msg *message = NULL;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_s32(message, PROCESS_A_SESSION, session);
    nla_put_u8(message, PROCESS_A_OP_TYPE, status);

    nl_send_auto(NetlinkGetNlSock(), message);
    nlmsg_free(message);
    return 0;
}

int ProcProtectEnable(int32_t session) {
    return ProcProtectStatusUpdate(session, PROCESS_PROTECT_ENABLE);
}
int ProcProtectDisable(int32_t session) {
    return ProcProtectStatusUpdate(session, PROCESS_PROTECT_DISABLE);
}

ProcPerm ProcPermCheck(char *cmd) {
    auto &auditor = Auditor::GetInstance();
    return auditor.HandlerNewCmd(cmd);
}

int ProcPermReply(ProcPermID id, ProcPerm perm) {
    struct nl_msg *message = NULL;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_u8(message, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
    nla_put_s32(message, PROCESS_A_ID, id);
    nla_put_s32(message, PROCESS_A_PERM, perm);
    nl_send_auto(NetlinkGetNlSock(), message);
    nlmsg_free(message);
    return 0;
}

static int ProcReportJsonGen(const std::string &cmd, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::proc::report";
    doc["cmd"] = cmd;
    msg = InternalJsonWrapper(doc);
    return 0;
}

static int ProcEnableJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::proc::enable";
    doc["code"] = code;
    msg = UserJsonWrapper(session, doc);
    return 0;
}

static int ProcDisableJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::proc::disable";
    doc["code"] = code;
    msg = UserJsonWrapper(session, doc);
    return 0;
}

int ProcProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
    int error, id, code, session;
    char *name;
    std::string msg;

    switch (type) {
    case PROCESS_PROTECT_ENABLE:
        session = nla_get_s32(genl_info->attrs[PROCESS_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
        ProcEnableJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        LOG("kernel::proc::enable, session=[%d] code=[%d]", session, code);
        break;

    case PROCESS_PROTECT_DISABLE:
        session = nla_get_s32(genl_info->attrs[PROCESS_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
        ProcDisableJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        LOG("kernel::proc::disable, session=[%d] code=[%d]", session, code);
        break;

    case PROCESS_PROTECT_REPORT:
        id = nla_get_s32(genl_info->attrs[PROCESS_A_ID]);
        name = nla_get_string(genl_info->attrs[PROCESS_A_NAME]);
        LOG("kernel::proc::report, id=[%d] name=[%s]", id, name);

        ProcReportJsonGen(name, msg);
        Broadcaster::GetInstance().Notify(msg);

        error = ProcPermReply(id, ProcPermCheck(name));
        if (error)
            ERR("reply_process_perm failed, id=[%d] name=[%s]", id, name);

        break;

    default:
        LOG("Unknown process protect command Type");
    }
    return 0;
}

}; // namespace hackernel
