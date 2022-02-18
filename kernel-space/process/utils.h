/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_PROCESS_UTILS_H
#define HACKERNEL_PROCESS_UTILS_H

#include <linux/kernel.h>

char *parse_argv_alloc(const char __user *const __user *argv);
char *get_pwd_path_alloc(void);

/* 用特殊ascii码间隔不同参数,0x1F是单元分隔符 */
#define ASCII_US 0x1F
#define ASCII_US_STR "\x1F"

#endif
