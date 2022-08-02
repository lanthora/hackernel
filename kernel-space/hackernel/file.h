/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include <net/genetlink.h>

enum {
	FILE_A_UNSPEC,
	FILE_A_SESSION,

	FILE_A_STATUS_CODE,
	FILE_A_OP_TYPE,
	FILE_A_NAME,
	FILE_A_PERM,
	FILE_A_FLAG,
	FILE_A_FSID,
	FILE_A_INO,
	__FILE_A_MAX,
};
#define FILE_A_MAX (__FILE_A_MAX - 1)

#define READ_WRITE_MASK 3

typedef unsigned long fsid_t;
typedef unsigned long ino_t;
typedef s32 file_perm_t;

#define READ_PROTECT_FLAG (1U << 0)
#define WRITE_PROTECT_FLAG (1U << 1)
#define UNLINK_PROTECT_FLAG (1U << 2)
#define RENAME_PROTECT_FLAG (1U << 3)
#define READ_AUDIT_FLAG (1U << 4)
#define WRITE_AUDIT_FLAG (1U << 5)
#define UNLINK_AUDIT_FLAG (1U << 6)
#define RENAME_AUDIT_FLAG (1U << 7)

#define RDWR_PROTECT_FLAG (READ_PROTECT_FLAG | WRITE_PROTECT_FLAG)
#define RDWR_AUDIT_FLAG (READ_AUDIT_FLAG | WRITE_AUDIT_FLAG)

#define BAD_FSID 0
#define BAD_INO 1
#define INVAILD_PERM 0

struct file_perm_data {
	char *path;
	fsid_t fsid;
	ino_t ino;
	file_perm_t this_perm;
	file_perm_t marked_perm;
};

struct file_perm_node {
	struct rb_node node;
	fsid_t fsid;
	ino_t ino;
	file_perm_t perm;
};

int file_perm_set(const fsid_t fsid, ino_t ino, file_perm_t perm, int flag);
int file_protect_enable(void);
int file_protect_disable(void);
int file_perm_tree_clear(void);
int file_protect_init(void);
int file_protect_destory(void);

enum {
	FILE_PROTECT_UNSPEC,
	FILE_PROTECT_REPORT,
	FILE_PROTECT_ENABLE,
	FILE_PROTECT_DISABLE,
	FILE_PROTECT_SET,
	FILE_PROTECT_CLEAR,
};

enum {
	FILE_UPDATE_FLAG_ANY,
	FILE_UPDATE_FLAG_NEW,
	FILE_UPDATE_FLAG_UPDATE,
};

int file_protect_handler(struct sk_buff *skb, struct genl_info *info);
int file_protect_report_event(struct file_perm_data *data);

#endif
