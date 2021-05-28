#ifndef HACKERNEL_FPERM_H
#define HACKERNEL_FPERM_H

#include <linux/kernel.h>

typedef unsigned long fsid_t;
typedef unsigned long ino_t;
typedef u32 perm_t;

#define READ_PROTECT_MASK 1
#define WRITE_PROTECT_MASK 2
#define UNLINK_PROTECT_MASK 4
#define RENAME_PROTECT_MASK 8

// fperm_init分配必要的内存,使用set/get前需要调用
// fperm_destory释放init和set过程中申请的内存
int fperm_init(void);
int fperm_destory(void);

// 根据文件系统id(fsid_t)和i节点号(ino_t),获取和设置保护模式
// 未设置任何保护模式时,获取到的权限(perm_t)为0
perm_t fperm_get(const fsid_t fsid, ino_t ino);
int fperm_set(const fsid_t fsid, ino_t ino, perm_t perm);

#endif
