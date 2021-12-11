#include "file/define.h"
#include "hackernel/file.h"

namespace hackernel {

int FileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;
    char *name;
    FilePerm perm;
    int code;

    type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
    switch (type) {
    // TODO: 根据业务分别处理case,目前只是打印日志
    case FILE_PROTECT_ENABLE:
    case FILE_PROTECT_DISABLE:
    case FILE_PROTECT_SET:
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        LOG("file ctrl response code=[%d]", code);
        break;

    case FILE_PROTECT_REPORT:
        name = nla_get_string(genl_info->attrs[FILE_A_NAME]);
        perm = nla_get_s32(genl_info->attrs[FILE_A_PERM]);
        LOG("file: name=[%s] perm=[%d]", name, perm);
        break;

    default:
        LOG("Unknown process protect command Type");
    }

    return 0;
}

}; // namespace hackernel
