#ifndef HACKERNEL_FPERM_H
#define HACKERNEL_FPERM_H

#include <linux/kernel.h>

typedef unsigned long fsid_t;
typedef unsigned long ino_t;
typedef s32 file_perm_t;

#define READ_PROTECT_MASK 1
#define WRITE_PROTECT_MASK 2
#define UNLINK_PROTECT_MASK 4
#define RENAME_PROTECT_MASK 8

#define BAD_FSID 0
#define BAD_INO 1
#define INVAILD_PERM INT_MIN

// file_perm_init 分配必要的内存,使用set/get前需要调用
// file_perm_destory 释放init和set过程中申请的内存
int file_perm_init(void);
int file_perm_destory(void);

// 根据文件系统id(fsid_t)和i节点号(ino_t),获取和设置保护模式
// 未设置任何保护模式时,获取到的权限(file_perm_t)为0
file_perm_t file_perm_get(const fsid_t fsid, ino_t ino);
int file_perm_set(const fsid_t fsid, ino_t ino, file_perm_t perm);

file_perm_t file_perm_get_path(const char *path);
int file_perm_set_path(const char *path, file_perm_t perm);

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

typedef s32 process_perm_t;
typedef int process_perm_id_t;

int process_perm_init(void);
int process_perm_destory(void);

// 添加序列号后进程休眠
int precess_perm_insert(process_perm_id_t seq);

// 唤醒前更新
int precess_perm_update(process_perm_id_t id, process_perm_t status);

// 等待队列退出等待条件检查时,PROCESS_WATT 继续等待,否则退出等待
process_perm_t precess_perm_search(process_perm_id_t id);

// 退出等待后,移除对应序列号中的数据
int precess_perm_delele(process_perm_id_t id);

#endif
