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
extern unsigned long *g_sys_call_table;

#define HKMAP1(cnt, m, t, a, ...) m(t, a, cnt)
#define HKMAP2(cnt, m, t, a, ...) m(t, a, cnt), HKMAP1(cnt##i, m, __VA_ARGS__)
#define HKMAP3(cnt, m, t, a, ...) m(t, a, cnt), HKMAP2(cnt##i, m, __VA_ARGS__)
#define HKMAP4(cnt, m, t, a, ...) m(t, a, cnt), HKMAP3(cnt##i, m, __VA_ARGS__)
#define HKMAP5(cnt, m, t, a, ...) m(t, a, cnt), HKMAP4(cnt##i, m, __VA_ARGS__)

#if CONFIG_SYSCALL_PTREG
#define __HOOK_DECL(t, a, cnt) t a
#define __HOOK_ARGS(t, a, cnt) (t) SC_ARG_##cnt
#define DECL_MAP(n, ...) HKMAP##n(i, __HOOK_DECL, __VA_ARGS__)
#define ARGS_MAP(n, ...) HKMAP##n(i, __HOOK_ARGS, __VA_ARGS__)
#define DECL_MAP_RAW(n, ...) struct pt_regs *regs
#define ARGS_MAP_RAW(n, ...) regs
#else
#define __HOOK_DECL(t, a, cnt) t a
#define __HOOK_ARGS(t, a, cnt) (t) a
#define DECL_MAP(n, ...) HKMAP##n(i, __HOOK_DECL, __VA_ARGS__)
#define ARGS_MAP(n, ...) HKMAP##n(i, __HOOK_ARGS, __VA_ARGS__)
#define DECL_MAP_RAW DECL_MAP
#define ARGS_MAP_RAW ARGS_MAP
#endif

#define HOOK_DEFINEx(x, name, ...)                                             \
	__diag_push();                                                         \
	__diag_ignore(GCC, 8, "-Wint-conversion", "");                         \
	static long __sys_##name##_hook(DECL_MAP(x, __VA_ARGS__));             \
	long sys_##name##_hook(DECL_MAP_RAW(x, __VA_ARGS__));                  \
	long (*hk_sys_##name)(DECL_MAP_RAW(x, __VA_ARGS__));                   \
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
	}                                                                      \
	long sys_##name##_hook(DECL_MAP_RAW(x, __VA_ARGS__))                   \
	{                                                                      \
		long retval;                                                   \
		retval = __sys_##name##_hook(ARGS_MAP(x, __VA_ARGS__));        \
		if (retval)                                                    \
			return retval;                                         \
		return hk_sys_##name(ARGS_MAP_RAW(x, __VA_ARGS__));            \
	}                                                                      \
	__diag_pop();                                                          \
	static long __sys_##name##_hook(DECL_MAP(x, __VA_ARGS__))

#define HOOK_DEFINE1(name, ...) HOOK_DEFINEx(1, name, __VA_ARGS__)
#define HOOK_DEFINE2(name, ...) HOOK_DEFINEx(2, name, __VA_ARGS__)
#define HOOK_DEFINE3(name, ...) HOOK_DEFINEx(3, name, __VA_ARGS__)
#define HOOK_DEFINE4(name, ...) HOOK_DEFINEx(4, name, __VA_ARGS__)
#define HOOK_DEFINE5(name, ...) HOOK_DEFINEx(5, name, __VA_ARGS__)

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
#define SC_ARG_i (regs->di)
#define SC_ARG_ii (regs->si)
#define SC_ARG_iii (regs->dx)
#define SC_ARG_iiii (regs->r10)
#define SC_ARG_iiiii (regs->r8)
#endif

#if defined(CONFIG_ARM)
/**
 * 32位ARM系统调用参数没有放到pt_regs数据结构里,而是直接作为函数参数传递
 */
#endif

#endif
