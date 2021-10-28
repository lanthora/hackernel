/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"
#include <linux/kernel.h>
#include <net/genetlink.h>
#include <net/netlink.h>

enum {
	FILE_A_UNSPEC,
	FILE_A_STATUS_CODE,
	FILE_A_OP_TYPE,
	FILE_A_NAME,
	FILE_A_PERM,
	__FILE_A_MAX,
};
#define FILE_A_MAX (__FILE_A_MAX - 1)

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

struct file_perm_data {
	char *path;
	fsid_t fsid;
	ino_t ino;
	file_perm_t this_perm;
	file_perm_t deny_perm;
};

struct file_perm_node {
	struct rb_node node;
	fsid_t fsid;
	ino_t ino;
	file_perm_t perm;
};

int file_perm_set_path(const char *path, file_perm_t perm);
int file_protect_enable(void);
int file_protect_disable(void);
int file_protect_init(void);
int file_protect_destory(void);

enum {
	FILE_PROTECT_UNSPEC,
	FILE_PROTECT_REPORT,
	FILE_PROTECT_ENABLE,
	FILE_PROTECT_DISABLE,
	FILE_PROTECT_SET
};
int file_protect_handler(struct sk_buff *skb, struct genl_info *info);
int file_protect_report_to_userspace(struct file_perm_data *data);

#endif
