/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "file/define.h"
#include "hackernel/util.h"
#include <netlink/genl/mngt.h>

namespace hackernel {

int FileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg);

enum { FILE_PROTECT_UNSPEC, FILE_PROTECT_REPORT, FILE_PROTECT_ENABLE, FILE_PROTECT_DISABLE, FILE_PROTECT_SET };

typedef int32_t FilePerm;

int FileProtectEnable(int32_t session);
int FileProtectDisable(int32_t session);
int FileProtectSet(int32_t session, const char *path, FilePerm perm);

#define FLAG_FILE_READ_DISABLE (1U << 0)
#define FLAG_FILE_WRITE_DISABLE (1U << 1)
#define FLAG_FILE_DELETE_DISABLE (1U << 2)
#define FLAG_FILE_RENAME_DISABLE (1U << 3)
#define FLAG_FILE_READ_AUDIT (1U << 4)
#define FLAG_FILE_WRITE_AUDIT (1U << 5)
#define FLAG_FILE_DELETE_AUDIT (1U << 6)
#define FLAG_FILE_RENAME_AUDIT (1U << 7)

}; // namespace hackernel

#endif
