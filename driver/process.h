#ifndef HACKERNEL_PROCESS_H
#define HACKERNEL_PROCESS_H

#include "syscall.h"
#include <net/genetlink.h>
#include <net/netlink.h>

DEFINE_HOOK_HEADER(execve);

extern int process_protect_handler(struct sk_buff *skb, struct genl_info *info);

#endif