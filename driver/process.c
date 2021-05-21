#include "process.h"
#include "syscall.h"
#include "util.h"
#include <linux/binfmts.h>
#include <linux/gfp.h>
#include <linux/slab.h>

static sys_call_ptr_t __x64_sys_execve = NULL;

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
static int sys_execve_hook(char __user *pathname, char __user *__user *argv,
			   char __user *__user *envp)
{
	char *cmd = NULL;
	int error = -1;

	cmd = kzalloc(MAX_ARG_STRLEN, GFP_KERNEL);
	if (!cmd) {
		error = -1;
		goto out;
	}
	error = parse_argv((const char *const *)argv, cmd, MAX_ARG_STRLEN);
	if (error) {
		goto out;
	}
	printk(KERN_INFO "hackernel: execve: %s\n", cmd);

out:
	kfree(cmd);
	return error;
}

asmlinkage u64 sys_execve_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;

	if (sys_execve_hook(pathname, argv, envp)) {
	}
	return __x64_sys_execve(regs);
}

int replace_execve(void)
{
	if (!g_sys_call_table) {
		printk(KERN_ERR "hackernel: must init syscall table\n");
		return -1;
	}

	if (__x64_sys_execve) {
		printk(KERN_ERR "hackernel: execve doulbe init\n");
		return 0;
	}

	__x64_sys_execve = g_sys_call_table[__NR_execve];
	disable_write_protection();
	g_sys_call_table[__NR_execve] = &sys_execve_wrapper;
	enable_write_protection();
	return 0;
}

int restore_execve(void)
{
	if (!g_sys_call_table) {
		return 0;
	}

	if (__x64_sys_execve) {
		disable_write_protection();
		g_sys_call_table[__NR_execve] = __x64_sys_execve;
		enable_write_protection();
		__x64_sys_execve = NULL;
	}

	return 0;
}
