#include "sys_execve.h"
#include "syscall.h"
#include "util.h"
#include <linux/syscalls.h>

static sys_call_ptr_t real_execve = NULL;

asmlinkage u64 custom_execve(const struct pt_regs *regs)
{
	const char *pathname = (const char *)regs->di;
	// 这种指针最后一个指针指向一个空字符串 "\0"
	const char *const *argv = (const char *const *)regs->si;
	const char *const *envp = (const char *const *)regs->dx;

	printk("hackernel: filename=%s", pathname);
	printk("hackernel: argv count=%d", count_strings(argv));
	return real_execve(regs);
}

int replace_execve(void)
{
	if (!g_sys_call_table) {
		printk("hackernel: g_sys_call_table must be initialized before calling replace_execve\n");
	}
	real_execve = g_sys_call_table[__NR_execve];
	disable_write_protect();
	g_sys_call_table[__NR_execve] = &custom_execve;
	enable_write_protect();
	return 0;
}

int restore_execve(void)
{
	if (!g_sys_call_table || !real_execve) {
		return 0;
	}
	disable_write_protect();
	g_sys_call_table[__NR_execve] = real_execve;
	enable_write_protect();
	return 0;
}
