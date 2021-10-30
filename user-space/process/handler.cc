#include "process.h"
#include <algorithm>
#include <string>

int ProcessProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                          void *arg) {
    u_int8_t type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
    int error, id, code;
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
        msg.assign(name);

        std::for_each(msg.begin(), msg.end(), [](char &c) {
            if (c == 0x1F)
                c = '#';
        });

        LOG("process: id=[%d] name=[%s]", id, msg.data());
        error = ProcessPermReply(id, ProcessPermCheck(name));
        if (error)
            LOG("reply_process_perm failed");

        break;

    default:
        LOG("Unknown process protect command Type");
    }
    return 0;
}
