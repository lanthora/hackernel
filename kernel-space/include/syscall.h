#ifndef HACKERNEL_SYSCALL_H
#define HACKERNEL_SYSCALL_H

#include "util.h"
#include <generated/autoconf.h>
#include <linux/kernel.h>

/**
 * 系统调用替换和恢复的实现，使用这个宏必须实现
 * unsigned long sys_name_hook(struct pt_regs *regs)
 * 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
 */
extern sys_call_ptr_t *g_sys_call_table;

#ifndef DEFINE_HOOK
#define DEFINE_HOOK(name)                                                      \
	static asmlinkage unsigned long sys_##name##_hook(                     \
		struct pt_regs *regs);                                         \
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
		disable_wp((phys_addr_t)(g_sys_call_table + __NR_##name));     \
		g_sys_call_table[__NR_##name] = &sys_##name##_hook;            \
		enable_wp((phys_addr_t)(g_sys_call_table + __NR_##name));      \
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
		disable_wp((phys_addr_t)(g_sys_call_table + __NR_##name));     \
		g_sys_call_table[__NR_##name] = hk_sys_##name;                 \
		enable_wp((phys_addr_t)(g_sys_call_table + __NR_##name));      \
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
#define HKSC_ARGV_ONE (regs->di)
#define HKSC_ARGV_TWO (regs->si)
#define HKSC_ARGV_THREE (regs->dx)
#define HKSC_ARGV_FOUR (regs->r10)
#define HKSC_ARGV_FIVE (regs->r8)
#endif

#if defined(CONFIG_ARM)
#define HKSC_ARGV_ONE (regs->uregs[1])
#define HKSC_ARGV_TWO (regs->uregs[2])
#define HKSC_ARGV_THREE (regs->uregs[3])
#define HKSC_ARGV_FOUR (regs->uregs[4])
#define HKSC_ARGV_FIVE (regs->uregs[5])
#endif

#endif
