/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_PROCESS_H
#define HACKERNEL_PROCESS_H

#include "hackernel/util.h"
#include "process/define.h"
#include <netlink/genl/mngt.h>

namespace hackernel {

typedef int ProcPermID;
typedef int32_t ProcPerm;

enum { PROCESS_PROTECT_UNSPEC, PROCESS_PROTECT_REPORT, PROCESS_PROTECT_ENABLE, PROCESS_PROTECT_DISABLE };

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

int handle_genl_proc_prot(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                          void *arg);

int enable_proc_protect(int32_t session);
int disable_proc_protect(int32_t session);

ProcPerm check_proc_perm(char *cmd);
int reply_proc_perm(ProcPermID id, ProcPerm perm);

}; // namespace hackernel

#endif
