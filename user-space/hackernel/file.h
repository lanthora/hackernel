/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "file/define.h"
#include "hackernel/util.h"
#include <netlink/genl/mngt.h>

namespace hackernel {

int handle_genl_file_prot(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                          void *arg);

enum { FILE_PROTECT_UNSPEC, FILE_PROTECT_REPORT, FILE_PROTECT_ENABLE, FILE_PROTECT_DISABLE, FILE_PROTECT_SET };

typedef int32_t file_perm;

int enable_file_prot(int32_t session);
int disable_file_prot(int32_t session);
int set_file_prot(int32_t session, const char *path, file_perm perm);

#define FLAG_FILE_DISABLE_READ (0b00000001)
#define FLAG_FILE_DISABLE_WRITE (0b00000010)
#define FLAG_FILE_DISABLE_DELETE (0b00000100)
#define FLAG_FILE_DISABLE_RENAME (0b00001000)
#define FLAG_FILE_DISABLE_ALL (0b00001111)
#define FLAG_FILE_AUDIT_READ (0b00010000)
#define FLAG_FILE_AUDIT_WRITE (0b00100000)
#define FLAG_FILE_AUDIT_DELETE (0b01000000)
#define FLAG_FILE_AUDIT_RENAME (0b10000000)
#define FLAG_FILE_AUDIT_ALL (0b11110000)

}; // namespace hackernel

#endif
