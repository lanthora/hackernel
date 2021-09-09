#ifndef HACKERNEL_DEFINE_H
#define HACKERNEL_DEFINE_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define CONFIG_KALLSYMS_LOOKUP_NAME 1
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0))
#define CONFIG_NLA_STRSCPY 1
#endif

#if defined(CONFIG_X86)
/**
 * 通过CONFIG_SYSCALL_PTREG宏来标记系统调用表的参数是否被封装
 * 目前只有x86设备和一台树莓派,可以简单的这样定义,这个定义在复杂
 * 场景下是一定会有问题的,等遇到新的问题再去改
 */
#define CONFIG_SYSCALL_PTREG 1
#endif

#ifndef CONFIG_KALLSYMS_LOOKUP_NAME
#define CONFIG_KALLSYMS_LOOKUP_NAME 0
#endif

#ifndef CONFIG_NLA_STRSCPY
#define CONFIG_NLA_STRSCPY 0
#endif

#ifndef CONFIG_SYSCALL_PTREG
#define CONFIG_SYSCALL_PTREG 0
#endif

#endif