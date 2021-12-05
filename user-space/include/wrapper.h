/**
 * C++函数封装成C函数供netlink的接口使用
 */

#ifndef HACKERNEL_WRAPPER_H
#define HACKERNEL_WRAPPER_H

#include "util.h"
#include <netlink/genl/mngt.h>

EXTERN_C_BEGIN

int keepalive_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg);

int process_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                            void *arg);
int file_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                         void *arg);
int net_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg);

EXTERN_C_END

#endif
