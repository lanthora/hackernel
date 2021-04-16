#include "sys_execve.h"
#include "syscall.h"
#include "util.h"
#include <linux/syscalls.h>

static sys_call_ptr_t real_execve = NULL;

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
static int sys_evecve(char __user *pathname, char __user *__user *argv,
		      char __user *__user *envp)
{
	char path[PATH_SIZE];
	char *params, *cursor;
	long size, idx, remain;

	size = strncpy_from_user((char *)&path, pathname, PATH_SIZE);
	if (!size) {
		printk(KERN_ERR "read pathname from user failed! pathname=%p\n",
		       pathname);
		return -1;
	}

	params = kzalloc(BUFFSIZE, GFP_KERNEL);

	for (idx = 0, size = 0, cursor = params; argv[idx]; ++idx) {
		remain = BUFFSIZE - (cursor - params);
		if (remain <= 0) {
			printk(KERN_WARNING
			       "hackernel: the parameter is too long and is truncated\n");
			break;
		}
		size = strncpy_from_user(cursor, argv[idx], remain);
		if (!size) {
			printk(KERN_ERR "read argv from user failed! argv=%p\n",
			       argv);
			break;
		}
		cursor += size;
		*(cursor++) = ' ';
	}
	*(cursor-1) = 0;

	//printk(KERN_INFO "hackernel: cmd[%ld]=%s\n", cursor-params, params);
	kfree(params);
	return 0;
}

asmlinkage u64 raw_sys_execve(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;
	
	if (sys_evecve(pathname, argv, envp)) {
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
