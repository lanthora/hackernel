#include "exclusive.h"

int ExclusiveHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    int code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
    if (code) {
        LOG("handshake response code=[%d]", code);
        LOG("handshake failed. exit");
        exit(1);
    }

    return 0;
}
