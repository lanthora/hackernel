#ifndef HACKERNEL_SYSCALL_H
#define HACKERNEL_SYSCALL_H

#include <linux/kernel.h>

typedef asmlinkage u64 (*sys_call_ptr_t)(struct pt_regs *);

extern sys_call_ptr_t *g_sys_call_table;

// 使用外部参数初始化系统调用表
int init_sys_call_table(u64 sys_call_table);

// 开关进程保护
int enable_process_protect(void);
int disable_process_protect(void);

// 开关文件保护
int enable_file_protect(void);
int disable_file_protect(void);

// 调整系统调用表的写保护状态
void disable_write_protection(void);
void enable_write_protection(void);

// 系统调用替换和恢复的函数声明
#ifndef DEFINE_HOOK_HEADER
#define DEFINE_HOOK_HEADER(name)                                               \
	int replace_##name(void);                                              \
	int restore_##name(void);
#endif

// 系统调用替换和恢复的实现，使用这个宏必须实现
// u64 sys_name_wrapper(struct pt_regs *regs)
// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
#ifndef DEFINE_HOOK
#define DEFINE_HOOK(name)                                                      \
	asmlinkage u64 sys_##name##_wrapper(struct pt_regs *regs);             \
	static sys_call_ptr_t __x64_sys_##name = NULL;                         \
	int replace_##name(void)                                               \
	{                                                                      \
		if (!g_sys_call_table) {                                       \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (__x64_sys_##name) {                                        \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		__x64_sys_##name = g_sys_call_table[__NR_##name];              \
                                                                               \
		disable_write_protection();                                    \
		g_sys_call_table[__NR_##name] = &sys_##name##_wrapper;         \
		enable_write_protection();                                     \
		return 0;                                                      \
	}                                                                      \
                                                                               \
	int restore_##name(void)                                               \
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
		__x64_sys_##name = NULL;                                       \
		return 0;                                                      \
	}
#endif

#endif
