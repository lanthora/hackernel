#ifndef HACKERNEL_SYSCALL_H
#define HACKERNEL_SYSCALL_H

#include "util.h"
#include <linux/kernel.h>

typedef asmlinkage u64 (*sys_call_ptr_t)(struct pt_regs *);

extern sys_call_ptr_t *g_sys_call_table;

int init_sys_call_table(u64 sys_call_table);

void disable_write_protection(void);
void enable_write_protection(void);

/**
 * 系统调用替换和恢复的实现，使用这个宏必须实现
 * u64 sys_name_hook(struct pt_regs *regs)
 * 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
 */
#ifndef DEFINE_HOOK
#define DEFINE_HOOK(name)                                                      \
	static asmlinkage u64 sys_##name##_hook(struct pt_regs *regs);         \
	static sys_call_ptr_t __x64_sys_##name = NULL;                         \
	static int replace_##name(void)                                        \
	{                                                                      \
		if (!g_sys_call_table) {                                       \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (!__x64_sys_##name) {                                       \
			__x64_sys_##name = g_sys_call_table[__NR_##name];      \
		}                                                              \
                                                                               \
		disable_write_protection();                                    \
		g_sys_call_table[__NR_##name] = &sys_##name##_hook;            \
		enable_write_protection();                                     \
		return 0;                                                      \
	}                                                                      \
                                                                               \
	static int restore_##name(void)                                        \
	{                                                                      \
		if (!g_sys_call_table) {                                       \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (!__x64_sys_##name) {                                       \
			return -EPERM;                                         \
		}                                                              \
		disable_write_protection();                                    \
		g_sys_call_table[__NR_##name] = __x64_sys_##name;              \
		enable_write_protection();                                     \
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

#endif
