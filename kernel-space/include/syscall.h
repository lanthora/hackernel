#ifndef HACKERNEL_SYSCALL_H
#define HACKERNEL_SYSCALL_H

#include "util.h"
#include <generated/autoconf.h>
#include <linux/kernel.h>

/**
 * 系统调用替换和恢复的实现，使用这个宏必须实现
 * long sys_name_hook(struct pt_regs *regs)
 * 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
 */
extern sys_call_ptr_t *g_sys_call_table;

#ifndef DEFINE_HOOK
#define DEFINE_HOOK(name)                                                      \
	static asmlinkage long sys_##name##_hook(struct pt_regs *regs);        \
	static sys_call_ptr_t hk_sys_##name = NULL;                            \
	static int replace_##name(void)                                        \
	{                                                                      \
		if (!g_sys_call_table) {                                       \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (!hk_sys_##name) {                                          \
			hk_sys_##name = g_sys_call_table[__NR_##name];         \
		}                                                              \
                                                                               \
		disable_wp((unsigned long)(g_sys_call_table + __NR_##name));   \
		g_sys_call_table[__NR_##name] = &sys_##name##_hook;            \
		enable_wp((unsigned long)(g_sys_call_table + __NR_##name));    \
		return 0;                                                      \
	}                                                                      \
                                                                               \
	static int restore_##name(void)                                        \
	{                                                                      \
		if (!g_sys_call_table) {                                       \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (!hk_sys_##name) {                                          \
			return -EPERM;                                         \
		}                                                              \
		disable_wp((unsigned long)(g_sys_call_table + __NR_##name));   \
		g_sys_call_table[__NR_##name] = hk_sys_##name;                 \
		enable_wp((unsigned long)(g_sys_call_table + __NR_##name));    \
		return 0;                                                      \
	}
#endif

#ifndef STR
#define STR(x) #x
#endif

#ifndef REG_HOOK
#define REG_HOOK(name)                                                         \
	do {                                                                   \
		if (replace_##name()) {                                        \
			LOG("replace_" STR(name) " failed");                   \
		}                                                              \
	} while (0)
#endif

#ifndef UNREG_HOOK
#define UNREG_HOOK(name)                                                       \
	do {                                                                   \
		if (restore_##name()) {                                        \
			LOG("restore_" STR(name) " failed");                   \
		}                                                              \
	} while (0)
#endif

#if defined(CONFIG_X86)
#define SC_ARG_1 (regs->di)
#define SC_ARG_2 (regs->si)
#define SC_ARG_3 (regs->dx)
#define SC_ARG_4 (regs->r10)
#define SC_ARG_5 (regs->r8)
#endif

#if defined(CONFIG_ARM)
/**
 * 32位ARM系统调用参数没有放到pt_regs数据结构里,而是直接作为函数参数传递
 */
#endif

#endif
