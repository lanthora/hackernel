#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "util.h"
#include <netlink/genl/mngt.h>

enum {
    FILE_A_UNSPEC,
    FILE_A_SESSION,

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
int FileProtectEnable(void);
int FileProtectDisable(void);
int FileProtectSet(const char *path, FilePerm perm);

#define FLAG_FILE_READ_DISABLE (1U << 0)
#define FLAG_FILE_WRITE_DISABLE (1U << 1)
#define FLAG_FILE_DELETE_DISABLE (1U << 2)
#define FLAG_FILE_RENAME_DISABLE (1U << 3)
#define FLAG_FILE_READ_WRITE (FLAG_FILE_DELETE_DISABLE | FLAG_FILE_RENAME_DISABLE)
#define FLAG_FILE_READ_ONLY (FLAG_FILE_WRITE_DISABLE | FLAG_FILE_READ_WRITE)
#define FLAG_RILE_WRITE_ONLY (FLAG_FILE_READ_DISABLE | FLAG_FILE_READ_WRITE)
#define FLAG_FILE_ALL_DISABLE (-1)

#endif
