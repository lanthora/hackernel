#include "handler.h"
#include "command.h"
#include "netlink.h"
#include "util.h"
#include <iostream>

int handshake_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    int code = nla_get_s32(genl_info->attrs[HACKERNEL_A_CODE]);
    LOG("handshake code=[%d]", code);
    return 0;
}

int process_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;
    if (!genl_info->attrs[HACKERNEL_A_TYPE]) {
        LOG("genl_info->attrs[HACKERNEL_A_TYPE] is null");
        return 0;
    }
    type = nla_get_u8(genl_info->attrs[HACKERNEL_A_TYPE]);
    switch (type) {
    case PROCESS_PROTECT_ENABLE: {
        int code;
        code = nla_get_s32(genl_info->attrs[HACKERNEL_A_CODE]);
        LOG("nla_get_s32 code=[%d]", code);
        break;
    }
    case PROCESS_PROTECT_REPORT: {
        int error;
        int id;
        char *name;

        id = nla_get_s32(genl_info->attrs[HACKERNEL_A_EXID]);
        name = nla_get_string(genl_info->attrs[HACKERNEL_A_NAME]);
        LOG("execve: name=[%s]", name);
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

    type = nla_get_u8(genl_info->attrs[HACKERNEL_A_TYPE]);
    switch (type) {
    case FILE_PROTECT_ENABLE:
    case FILE_PROTECT_DISABLE:
    case FILE_PROTECT_SET: {
        int code;

        code = nla_get_s32(genl_info->attrs[HACKERNEL_A_CODE]);
        LOG("file ctrl response code=[%d]", code);
        break;
    }
    case FILE_PROTECT_REPORT: {
        char *name;
        file_perm_t perm;

        name = nla_get_string(genl_info->attrs[HACKERNEL_A_NAME]);
        perm = nla_get_s32(genl_info->attrs[HACKERNEL_A_PERM]);

        LOG("open: name=[%s] perm=[%d]", name, perm);
        break;
    }
    default: {
        LOG("Unknown process protect command type");
    }
    }

    return 0;
}
