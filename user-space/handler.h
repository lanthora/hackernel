#ifndef HACKERNEL_HANDLER_H
#define HACKERNEL_HANDLER_H

#include <netlink/genl/mngt.h>

#ifdef __cplusplus
extern "C" {
#endif

int HandshakeHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                     struct genl_info *genl_info, void *arg);
int ProcessProtectHandler(struct nl_cache_ops *unused,
                          struct genl_cmd *genl_cmd,
                          struct genl_info *genl_info, void *arg);
int FileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                       struct genl_info *genl_info, void *arg);
int NetProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                      struct genl_info *genl_info, void *arg);

#ifdef __cplusplus
}
#endif

#endif