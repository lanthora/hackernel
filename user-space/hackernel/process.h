#ifndef HACKERNEL_PROCESS_H
#define HACKERNEL_PROCESS_H

#include "hackernel/util.h"
#include "process/define.h"
#include <netlink/genl/mngt.h>

namespace hackernel {

typedef int ProcessPermID;
typedef int32_t ProcessPerm;

enum { PROCESS_PROTECT_UNSPEC, PROCESS_PROTECT_REPORT, PROCESS_PROTECT_ENABLE, PROCESS_PROTECT_DISABLE };

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

int ProcessProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                          void *arg);

int ProcessProtectEnable(void);
int ProcessProtectDisable(void);
ProcessPerm ProcessPermCheck(char *cmd);
int ProcessPermReply(ProcessPermID id, ProcessPerm perm);

};  // namespace hackernel

#endif
