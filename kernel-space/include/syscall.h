#ifndef HACKERNEL_SYSCALL_H
#define HACKERNEL_SYSCALL_H

#include "define.h"
#include "util.h"
#include <linux/kernel.h>

extern unsigned long *g_sys_call_table;

#define HKMAP1(cnt, m, t, a, ...) m(t, a, cnt)
#define HKMAP2(cnt, m, t, a, ...) m(t, a, cnt), HKMAP1(cnt##i, m, __VA_ARGS__)
#define HKMAP3(cnt, m, t, a, ...) m(t, a, cnt), HKMAP2(cnt##i, m, __VA_ARGS__)
#define HKMAP4(cnt, m, t, a, ...) m(t, a, cnt), HKMAP3(cnt##i, m, __VA_ARGS__)
#define HKMAP5(cnt, m, t, a, ...) m(t, a, cnt), HKMAP4(cnt##i, m, __VA_ARGS__)

#if CONFIG_SYSCALL_PTREGS
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

#define REG_DEFINE(name)                                                       \
	static int __hook_##name(void)                                         \
	{                                                                      \
		if (HK_NR_##name == HK_NR_UNDEFINED) {                         \
			LOG("undefined system call: " STR(name));              \
			return -ENOSYS;                                        \
		}                                                              \
		if (!g_sys_call_table) {                                       \
			LOG("g_sys_call_table is not initialized");            \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (!hk_sys_##name) {                                          \
			hk_sys_##name = g_sys_call_table[HK_NR_##name];        \
		}                                                              \
                                                                               \
		disable_wp((unsigned long)(g_sys_call_table + HK_NR_##name));  \
		g_sys_call_table[HK_NR_##name] = &sys_##name##_hook;           \
		enable_wp((unsigned long)(g_sys_call_table + HK_NR_##name));   \
		return 0;                                                      \
	}

#define UNREG_DEFINE(name)                                                     \
	static int __unhook_##name(void)                                       \
	{                                                                      \
		if (HK_NR_##name == HK_NR_UNDEFINED) {                         \
			return -ENOSYS;                                        \
		}                                                              \
		if (!g_sys_call_table) {                                       \
			return -EPERM;                                         \
		}                                                              \
                                                                               \
		if (!hk_sys_##name) {                                          \
			return -EPERM;                                         \
		}                                                              \
		disable_wp((unsigned long)(g_sys_call_table + HK_NR_##name));  \
		g_sys_call_table[HK_NR_##name] = hk_sys_##name;                \
		enable_wp((unsigned long)(g_sys_call_table + HK_NR_##name));   \
		return 0;                                                      \
	}

#define HOOK_DEFINEx(x, name, ...)                                             \
	__diag_push();                                                         \
	__diag_ignore(GCC, 8, "-Wint-conversion", "");                         \
	static long __sys_##name##_hook(DECL_MAP(x, __VA_ARGS__));             \
	long sys_##name##_hook(DECL_MAP_RAW(x, __VA_ARGS__));                  \
	long (*hk_sys_##name)(DECL_MAP_RAW(x, __VA_ARGS__));                   \
	long sys_##name##_hook(DECL_MAP_RAW(x, __VA_ARGS__))                   \
	{                                                                      \
		long retval;                                                   \
		retval = __sys_##name##_hook(ARGS_MAP(x, __VA_ARGS__));        \
		if (retval)                                                    \
			return retval;                                         \
		return hk_sys_##name(ARGS_MAP_RAW(x, __VA_ARGS__));            \
	}                                                                      \
	REG_DEFINE(name)                                                       \
	UNREG_DEFINE(name)                                                     \
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
		__hook_##name();                                               \
	} while (0)
#endif

#ifndef UNREG_HOOK
#define UNREG_HOOK(name)                                                       \
	do {                                                                   \
		__unhook_##name();                                             \
	} while (0)
#endif

#if defined(CONFIG_X86_64)
#define SC_ARG_i (regs->di)
#define SC_ARG_ii (regs->si)
#define SC_ARG_iii (regs->dx)
#define SC_ARG_iiii (regs->r10)
#define SC_ARG_iiiii (regs->r8)
#endif

#if defined(CONFIG_ARM64)
#define SC_ARG_i (regs->regs[0])
#define SC_ARG_ii (regs->regs[1])
#define SC_ARG_iii (regs->regs[2])
#define SC_ARG_iiii (regs->regs[3])
#define SC_ARG_iiiii (regs->regs[4])
#endif

#endif
