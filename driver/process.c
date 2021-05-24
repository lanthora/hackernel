#include "process.h"
#include "syscall.h"
#include "util.h"
#include <linux/binfmts.h>
#include <linux/gfp.h>
#include <linux/slab.h>

DEFINE_HOOK(execve);

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
