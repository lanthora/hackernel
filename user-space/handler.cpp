#include "handler.h"
#include "command.h"
#include "netlink.h"
#include "util.h"
#include <iostream>

int handshake_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    int code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
    LOG("handshake response code=[%d]", code);
    return 0;
}

int process_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;
    if (!genl_info->attrs[PROCESS_A_OP_TYPE]) {
        LOG("invaild args, missing PROCESS_A_OP_TYPE");
        return 0;
    }
    type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
    switch (type) {
    case PROCESS_PROTECT_ENABLE: {
        int code;
        code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
        LOG("process ctl enable response code=[%d]", code);
        break;
    }
    case PROCESS_PROTECT_REPORT: {
        int error;
        int id;
        char *name;

        id = nla_get_s32(genl_info->attrs[PROCESS_A_ID]);
        name = nla_get_string(genl_info->attrs[PROCESS_A_NAME]);
        LOG("process: name=[%s]", name);
        error = reply_process_perm(id, check_precess_perm(name));
        if (error) {
            LOG("reply_process_perm failed");
        }
        break;
    }
    default: {
        LOG("Unknown process protect command type");
    }
    }
    return 0;
}

int file_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;

    type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
    switch (type) {
    // 这三个命令暂时公用一个响应处理函数
    case FILE_PROTECT_ENABLE:
    case FILE_PROTECT_DISABLE:
    case FILE_PROTECT_SET: {
        int code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        LOG("file ctrl response code=[%d]", code);
        break;
    }
    case FILE_PROTECT_REPORT: {
        char *name;
        file_perm_t perm;

        name = nla_get_string(genl_info->attrs[FILE_A_NAME]);
        perm = nla_get_s32(genl_info->attrs[FILE_A_PERM]);

        LOG("file: name=[%s] perm=[%d]", name, perm);
        break;
    }
    default: {
        LOG("Unknown process protect command type");
    }
    }

    return 0;
}

int net_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;

    type = nla_get_u8(genl_info->attrs[NET_A_OP_TYPE]);
    switch (type) {
    // 这三个命令暂时公用一个响应处理函数
    case NET_PROTECT_ENABLE:
    case NET_PROTECT_DISABLE:
    case NET_PROTECT_SET:
    case NET_PROTECT_REPORT:
    default:
        LOG("Unknown net protect command type");
    }

    return 0;
}
