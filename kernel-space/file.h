#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"
#include <linux/kernel.h>
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

typedef unsigned long fsid_t;
typedef unsigned long ino_t;
typedef s32 file_perm_t;

#define READ_PROTECT_MASK 1
#define WRITE_PROTECT_MASK 2
#define UNLINK_PROTECT_MASK 4
#define RENAME_PROTECT_MASK 8

#define BAD_FSID 0
#define BAD_INO 1
#define INVAILD_PERM 0

// file_perm_init 分配必要的内存,使用set/get前需要调用
// file_perm_destory 释放init和set过程中申请的内存
int file_perm_init(void);
int file_perm_destory(void);

enum {
	FILE_PROTECT_UNSPEC,
	FILE_PROTECT_REPORT,
	FILE_PROTECT_ENABLE,
	FILE_PROTECT_DISABLE,
	FILE_PROTECT_SET
};

extern int file_protect_handler(struct sk_buff *skb, struct genl_info *info);

// 开关文件保护
int enable_file_protect(void);
int disable_file_protect(void);
#endif
