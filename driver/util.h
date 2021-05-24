#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#include <linux/kernel.h>
#include <linux/sched.h>

int parse_pathname(const char __user *pathname, char *path, long size);
int parse_argv(const char __user *const __user *argv, char *params, long size);

// 获取某个task的工作目录,外部申请buffer传入,函数内部不申请内存,返回值为指向buffer内指针
char *get_exec_path(struct task_struct *task, void *buffer, size_t buffer_size);
char *get_cw_path(void *buffer, size_t buffer_size);

// 根据目录文件描述符和用户空间传入的参数获得绝对路径
// 函数内会申请内存,调用方需要释放内存
char *get_absolute_path_alloc(int dirfd, char __user *pathname);

// 黑白名单的匹配
#define PATH_MIN 64
int is_prefix_or_complate_match(const char *modle, const char *string);
int list_contain_top_down(const char (*list)[PATH_MIN], const char *filename);
int list_contain_bottom_up(const char (*list)[PATH_MIN], const char *filename);

// 获取inode number
unsigned long get_ino_by_path(int dfd, const char __user *name);

#endif
