#include "wrapper.h"
#include "file.h"
#include "keepalive.h"
#include "net.h"
#include "process.h"

int process_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                            void *arg) {
    return ProcessProtectHandler(unused, genl_cmd, genl_info, arg);
}
int file_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                         void *arg) {
    return FileProtectHandler(unused, genl_cmd, genl_info, arg);
}
int net_protect_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                        void *arg) {
    return NetProtectHandler(unused, genl_cmd, genl_info, arg);
}

int keepalive_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    return KeepAliveHandler(unused, genl_cmd, genl_info, arg);
}