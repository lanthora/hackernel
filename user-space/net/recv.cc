#include "hackernel/net.h"

namespace hackernel {

int NetProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;
    int code;

    type = nla_get_u8(genl_info->attrs[NET_A_OP_TYPE]);
    switch (type) {
    case NET_PROTECT_ENABLE:
    case NET_PROTECT_DISABLE:
    case NET_PROTECT_INSERT:
    case NET_PROTECT_DELETE:
        code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
        LOG("net ctrl response code=[%d]", code);
        break;

    default:
        LOG("Unknown net protect command Type");
    }
    return 0;
}

};  // namespace hackernel
