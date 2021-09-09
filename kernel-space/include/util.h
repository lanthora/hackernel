#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#include "define.h"
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uuid.h>
#include <linux/version.h>

char *parse_argv_alloc(const char __user *const __user *argv);
char *get_root_path_alloc(void);
char *get_pwd_path_alloc(void);
char *get_current_process_path_alloc(void);
char *get_absolute_path_alloc(int dirfd, char __user *pathname);
char *get_parent_path_alloc(const char *path);

unsigned long get_fsid(const char *name);
unsigned long get_ino(const char *name);
int file_id_get(const char *name, unsigned long *fsid, unsigned long *ino);

char *adjust_path(char *path);

#ifdef DEBUG
#define LOG(fmt, arg...)                                                       \
	do {                                                                   \
		printk(KERN_ERR "hackernel: %s:%d " fmt "\n", __FILE__,        \
		       __LINE__, ##arg);                                       \
	} while (0)
#else
#define LOG(fmt, arg...)
#endif

/* 用特殊ascii码间隔不同参数,0x1F是单元分隔符 */
#define ASCII_US 0x1F
#define ASCII_US_STR "\x1F"

void disable_wp(unsigned long addr);
void enable_wp(unsigned long addr);

#define spaceship(a, b) ((a == b) ? 0 : ((a > b) ? 1 : -1))

#if CONFIG_KALLSYMS_LOOKUP_NAME
#include <linux/kprobes.h>
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t hk_kallsyms_lookup_name;
#else
#define hk_kallsyms_lookup_name kallsyms_lookup_name
#endif

void util_init(void);

#endif
