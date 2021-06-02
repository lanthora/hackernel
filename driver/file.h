#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"
#include <net/genetlink.h>
#include <net/netlink.h>

DEFINE_HOOK_HEADER(open);
DEFINE_HOOK_HEADER(openat);
DEFINE_HOOK_HEADER(unlinkat);
DEFINE_HOOK_HEADER(renameat2);

#define FILE_PROTECT_ENABLE 1
#define FILE_PROTECT_DISABLE 2
#define FILE_PROTECT_SET 3
#define FILE_PROTECT_NOTIFY 4

extern int file_protect_handler(struct sk_buff *skb, struct genl_info *info);

#endif