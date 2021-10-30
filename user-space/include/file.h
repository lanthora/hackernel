#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "util.h"
#include <netlink/genl/mngt.h>

EXTERN_C_BEGIN

enum {
    FILE_A_UNSPEC,
    FILE_A_STATUS_CODE,
    FILE_A_OP_TYPE,
    FILE_A_NAME,
    FILE_A_PERM,
    __FILE_A_MAX,
};
#define FILE_A_MAX (__FILE_A_MAX - 1)

int FileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg);

enum { FILE_PROTECT_UNSPEC, FILE_PROTECT_REPORT, FILE_PROTECT_ENABLE, FILE_PROTECT_DISABLE, FILE_PROTECT_SET };

typedef int32_t FilePerm;
int FileProtectEnable();
int FileProtectDisable();
int FileProtectSet(const char *path, FilePerm perm);

#define READ_PROTECT_FLAG 1
#define WRITE_PROTECT_FLAG 2
#define UNLINK_PROTECT_FLAG 4
#define RENAME_PROTECT_FLAG 8
#define ALL_FILE_PROTECT_FLAG 15

EXTERN_C_END

#endif
