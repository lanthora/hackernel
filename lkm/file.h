#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"
#include <net/genetlink.h>
#include <net/netlink.h>

DEFINE_HOOK_HEADER(open);
DEFINE_HOOK_HEADER(openat);
DEFINE_HOOK_HEADER(unlink);
DEFINE_HOOK_HEADER(unlinkat);
DEFINE_HOOK_HEADER(rename);
DEFINE_HOOK_HEADER(renameat);
DEFINE_HOOK_HEADER(renameat2);
DEFINE_HOOK_HEADER(mkdir);
DEFINE_HOOK_HEADER(mkdirat);
DEFINE_HOOK_HEADER(rmdir);
DEFINE_HOOK_HEADER(link);
DEFINE_HOOK_HEADER(linkat);
DEFINE_HOOK_HEADER(symlink);
DEFINE_HOOK_HEADER(symlinkat);
DEFINE_HOOK_HEADER(mknod);
DEFINE_HOOK_HEADER(mknodat);

#define READ_WRITE_MASK 3

enum {
	FILE_PROTECT_UNSPEC,
	FILE_PROTECT_REPORT,
	FILE_PROTECT_ENABLE,
	FILE_PROTECT_DISABLE,
	FILE_PROTECT_SET
};

extern int file_protect_handler(struct sk_buff *skb, struct genl_info *info);

#endif
