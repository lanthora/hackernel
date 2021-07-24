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

struct file_perm_data {
	char *path;
	fsid_t fsid;
	ino_t ino;
	file_perm_t this_perm;
	file_perm_t deny_perm;
};

struct file_perm_node {
	struct rb_node node;
	ino_t ino;
	file_perm_t perm;
};

struct file_perm_list {
	struct list_head node;
	struct rb_root *root;
	fsid_t fsid;
};

int file_perm_set_path(const char *path, file_perm_t perm);

int enable_file_protect(void);
int disable_file_protect(void);

#endif
