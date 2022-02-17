/* SPDX-License-Identifier: GPL-2.0-only */
#include "nlc/wrapper.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/net.h"
#include "hackernel/process.h"

int process_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                            void *arg) {
    return hackernel::ProcProtectHandler(unused, genl_cmd, genl_info, arg);
}
int file_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                         void *arg) {
    return hackernel::FileProtectHandler(unused, genl_cmd, genl_info, arg);
}
int net_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                        void *arg) {
    return hackernel::NetProtectHandler(unused, genl_cmd, genl_info, arg);
}

int heartbeat_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    return hackernel::HeartbeatHandler(unused, genl_cmd, genl_info, arg);
}
