#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"
#include <linux/kernel.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#define READ_WRITE_MASK 3

typedef unsigned long fsid_t;
typedef unsigned long ino_t;
typedef s32 file_perm_t;

#define READ_PROTECT_FLAG 1
#define WRITE_PROTECT_FLAG 2
#define UNLINK_PROTECT_FLAG 4
#define RENAME_PROTECT_FLAG 8

#define BAD_FSID 0
#define BAD_INO 1
#define INVAILD_PERM 0

enum {
	FILE_PROTECT_UNSPEC,
	FILE_PROTECT_REPORT,
	FILE_PROTECT_ENABLE,
	FILE_PROTECT_DISABLE,
	FILE_PROTECT_SET
};

int file_protect_handler(struct sk_buff *skb, struct genl_info *info);
void exit_file_protect(void);
#endif
