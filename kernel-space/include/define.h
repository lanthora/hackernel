/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HACKERNEL_DEFINE_H
#define HACKERNEL_DEFINE_H

#include <generated/autoconf.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define CONFIG_KALLSYMS_LOOKUP_NAME 1
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0))
#define CONFIG_NLA_STRSCPY 1
#endif

/**
 * 通过CONFIG_SYSCALL_PTREGS宏标记系统调用表的参数是否被封装
 * 对已经确定被封装的系统设置宏为1
 */
#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
#define CONFIG_SYSCALL_PTREGS 1
#endif

#ifndef CONFIG_KALLSYMS_LOOKUP_NAME
#define CONFIG_KALLSYMS_LOOKUP_NAME 0
#endif

#ifndef CONFIG_NLA_STRSCPY
#define CONFIG_NLA_STRSCPY 0
#endif

#ifndef CONFIG_SYSCALL_PTREGS
#define CONFIG_SYSCALL_PTREGS 0
#endif

#define HK_NR_UNDEFINED -1

#if defined(__NR_open)
#define HK_NR_open __NR_open
#else
#define HK_NR_open HK_NR_UNDEFINED
#endif

#if defined(__NR_openat)
#define HK_NR_openat __NR_openat
#else
#define HK_NR_openat HK_NR_UNDEFINED
#endif

#if defined(__NR_openat)
#define HK_NR_openat __NR_openat
#else
#define HK_NR_openat HK_NR_UNDEFINED
#endif

#if defined(__NR_rename)
#define HK_NR_rename __NR_rename
#else
#define HK_NR_rename HK_NR_UNDEFINED
#endif

#if defined(__NR_renameat)
#define HK_NR_renameat __NR_renameat
#else
#define HK_NR_renameat HK_NR_UNDEFINED
#endif

#if defined(__NR_renameat2)
#define HK_NR_renameat2 __NR_renameat2
#else
#define HK_NR_renameat2 HK_NR_UNDEFINED
#endif

#if defined(__NR_mkdir)
#define HK_NR_mkdir __NR_mkdir
#else
#define HK_NR_mkdir HK_NR_UNDEFINED
#endif

#if defined(__NR_mkdirat)
#define HK_NR_mkdirat __NR_mkdirat
#else
#define HK_NR_mkdirat HK_NR_UNDEFINED
#endif

#if defined(__NR_rmdir)
#define HK_NR_rmdir __NR_rmdir
#else
#define HK_NR_rmdir HK_NR_UNDEFINED
#endif

#if defined(__NR_link)
#define HK_NR_link __NR_link
#else
#define HK_NR_link HK_NR_UNDEFINED
#endif

#if defined(__NR_linkat)
#define HK_NR_linkat __NR_linkat
#else
#define HK_NR_linkat HK_NR_UNDEFINED
#endif

#if defined(__NR_unlink)
#define HK_NR_unlink __NR_unlink
#else
#define HK_NR_unlink HK_NR_UNDEFINED
#endif

#if defined(__NR_unlinkat)
#define HK_NR_unlinkat __NR_unlinkat
#else
#define HK_NR_unlinkat HK_NR_UNDEFINED
#endif

#if defined(__NR_symlink)
#define HK_NR_symlink __NR_symlink
#else
#define HK_NR_symlink HK_NR_UNDEFINED
#endif

#if defined(__NR_symlinkat)
#define HK_NR_symlinkat __NR_symlinkat
#else
#define HK_NR_symlinkat HK_NR_UNDEFINED
#endif

#if defined(__NR_mknod)
#define HK_NR_mknod __NR_mknod
#else
#define HK_NR_mknod HK_NR_UNDEFINED
#endif

#if defined(__NR_mknodat)
#define HK_NR_mknodat __NR_mknodat
#else
#define HK_NR_mknodat HK_NR_UNDEFINED
#endif

#if defined(__NR_execve)
#define HK_NR_execve __NR_execve
#else
#define HK_NR_execve HK_NR_UNDEFINED
#endif

#if defined(__NR_execveat)
#define HK_NR_execveat __NR_execveat
#else
#define HK_NR_execveat HK_NR_UNDEFINED
#endif

#if defined(__NR_kill)
#define HK_NR_kill __NR_kill
#else
#define HK_NR_kill HK_NR_UNDEFINED
#endif

#endif