#include "hackernel/broadcaster.h"
#include "hackernel/process.h"
#include <algorithm>
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

static int ProcReportJsonGen(const std::string &cmd, std::string &msg) {
    nlohmann::json report;
    report["type"] = "proc::report";
    report["cmd"] = cmd;
    msg = report.dump();
    return 0;
}

int ProcProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
    int error, id, code, session;
    char *name;
    std::string msg;

    switch (type) {
    case PROCESS_PROTECT_ENABLE:
        code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
        LOG("process ctl enable response code=[%d]", code);
        break;

    case PROCESS_PROTECT_REPORT:
        id = nla_get_s32(genl_info->attrs[PROCESS_A_ID]);
        name = nla_get_string(genl_info->attrs[PROCESS_A_NAME]);
        LOG("process: id=[%d] name=[%s]", id, name);

        ProcReportJsonGen(name, msg);
        Broadcaster::GetInstance().Notify(msg);

        error = ProcPermReply(id, ProcPermCheck(name));
        if (error)
            LOG("reply_process_perm failed");

        break;

    default:
        LOG("Unknown process protect command Type");
    }
    return 0;
}

}; // namespace hackernel
