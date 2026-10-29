/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_DEFINE_H
#define HACKERNEL_DEFINE_H

#include <generated/autoconf.h>
#include <linux/syscalls.h>
#include <linux/version.h>

/*
 * x86 stopped dispatching through sys_call_table in v6.9. The change was
 * also backported to these stable branches. Distributions with different
 * backports can override this at build time with -DHACKERNEL_USE_FTRACE=0/1.
 * ARM and ARM64 retain the existing syscall-table backend.
 */
#ifndef HACKERNEL_USE_FTRACE
#if defined(CONFIG_X86_64) &&                                            \
	((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)) ||               \
	 (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 5) &&                \
	  LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)) ||                \
	 (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 26) &&               \
	  LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)) ||                \
	 (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 85) &&               \
	  LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)) ||                \
	 (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 154) &&             \
	  LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)))
#define HACKERNEL_USE_FTRACE 1
#else
#define HACKERNEL_USE_FTRACE 0
#endif
#endif

#if HACKERNEL_USE_FTRACE && !defined(CONFIG_X86_64)
#error "The ftrace syscall backend currently supports only x86_64"
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

#if defined(__NR_delete_module)
#define HK_NR_delete_module __NR_delete_module
#else
#define HK_NR_delete_module HK_NR_UNDEFINED
#endif

#endif
