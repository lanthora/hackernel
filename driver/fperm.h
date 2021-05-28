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

// 分配和释放必要的内存,fperm_exit会释放所有数据的内存
// 内核模块移除前需要调用fperm_exit
void fperm_init(void);
void fperm_exit(void);

// 根据文件系统id(fsid_t)和i节点号(ino_t),获取和设置保护模式
// 未设置任何保护模式时,获取到的权限(perm_t)为0
perm_t fperm_get(const fsid_t fsid, ino_t ino);
int fperm_set(const fsid_t fsid, ino_t ino, perm_t perm);

#endif
