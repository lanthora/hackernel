#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uuid.h>

int parse_pathname(const char __user *pathname, char *path, long size);
int parse_argv(const char __user *const __user *argv, char *params, long size);

char *get_root_path_alloc(void);
char *get_pwd_path_alloc(void);
char *get_current_process_path_alloc(void);

// 根据目录文件描述符和用户空间传入的参数获得绝对路径
// 函数内会申请内存,调用方需要释放内存
char *get_absolute_path_alloc(int dirfd, char __user *pathname);

// 获取全局路径的父路径,要求路径中不能包含任何相对路径信息
// 函数内会申请内存,调用方需要释放内存
char *get_parent_path_alloc(const char *path);

// 获取文件系统id和文件描述符id,通过这两个id可以唯一确定操作系统中的一个文件
unsigned long get_fsid(const char *name);
unsigned long get_ino(const char *name);
int file_id_get(const char *name, unsigned long *fsid, unsigned long *ino);

// 调整路径
char *adjust_path(char *path);

// 打印错误日志,内核中应该尽可能地不打印日志
#ifdef DEBUG
#define LOG(fmt, arg...)                                                       \
	do {                                                                   \
		printk(KERN_ERR "hackernel: %s:%d " fmt "\n", __FILE__,        \
		       __LINE__, ##arg);                                       \
	} while (0)
#else
#define LOG(fmt, arg...)
#endif

// 用特殊ascii码间隔不同参数,0x1F是单元分隔符
#define ASCII_US 0x1F
#define ASCII_US_STR "\x1F"
#endif
