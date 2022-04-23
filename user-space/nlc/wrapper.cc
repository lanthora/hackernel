/* SPDX-License-Identifier: GPL-2.0-only */
#include "nlc/wrapper.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/net.h"
#include "hackernel/process.h"

int process_protection_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                               void *arg) {
    return hackernel::handle_genl_process_protection(unused, genl_cmd, genl_info, arg);
}
int file_protection_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                            void *arg) {
    return hackernel::handle_genl_file_protection(unused, genl_cmd, genl_info, arg);
}
int net_protection_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                           void *arg) {
    return hackernel::handle_genl_net_protection(unused, genl_cmd, genl_info, arg);
}

int heartbeat_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    return hackernel::handle_heartbeat(unused, genl_cmd, genl_info, arg);
}
