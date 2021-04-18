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
	char *path = NULL, *params = NULL;
	int error = 0;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		printk(KERN_ERR "hackernel: kmalloc path failed!\n");
		error = -1;
		goto out;
	}

	parse_pathname(pathname, path, PATH_MAX);
	printk(KERN_INFO "hackernel: path=%s\n", path);

	params = kzalloc(ARG_MAX, GFP_KERNEL);
	if (!params) {
		printk(KERN_ERR "hackernel: kmalloc params failed!\n");
		error = -1;
		goto out;
	}
	parse_argv((const char *const *)argv, params, ARG_MAX);
	printk(KERN_INFO "hackernel: cmd=%s\n", params);

out:
	kfree(path);
	kfree(params);
	return error;
}

asmlinkage u64 raw_sys_execve(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;

	static atomic_t running_execve_cnt = ATOMIC_INIT(0);
	int cnt = atomic_inc_return(&running_execve_cnt);
	if (cnt > 1) {
		restore_execve();
	}
	if (sys_evecve(pathname, argv, envp)) {
		restore_execve();
	}
	atomic_dec(&running_execve_cnt);
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
