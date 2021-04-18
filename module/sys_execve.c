#include "sys_execve.h"
#include "syscall.h"
#include "util.h"
#include <linux/binfmts.h>
#include <linux/syscalls.h>

static sys_call_ptr_t real_execve = NULL;

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
static int sys_evecve(char __user *pathname, char __user *__user *argv,
		      char __user *__user *envp)
{
	char *cmd = NULL;
	int error = 0;

	cmd = kzalloc(ARG_MAX, GFP_KERNEL);
	if (!cmd) {
		error = -1;
		goto out;
	}
	parse_argv((const char *const *)argv, cmd, ARG_MAX);
	printk(KERN_INFO "hackernel: cmd=%s\n", cmd);

out:
	kfree(cmd);
	return error;
}

asmlinkage u64 raw_sys_execve(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;

	if (sys_evecve(pathname, argv, envp)) {
		restore_execve();
	}
	return real_execve(regs);
}

int replace_execve(void)
{
	if (!g_sys_call_table) {
		printk(KERN_ERR
		       "hackernel: g_sys_call_table must be initialized before calling replace_execve\n");
		return -1;
	}
	real_execve = g_sys_call_table[__NR_execve];
	disable_write_protection();
	g_sys_call_table[__NR_execve] = &raw_sys_execve;
	enable_write_protection();
	return 0;
}

int restore_execve(void)
{
	if (!g_sys_call_table || !real_execve) {
		printk(KERN_WARNING
		       "hackernel: restore_execve before replace\n");
		return 0;
	}
	disable_write_protection();
	g_sys_call_table[__NR_execve] = real_execve;
	enable_write_protection();
	return 0;
}
