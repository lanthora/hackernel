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
	char *path = NULL, *params = NULL, **p, *cursor;
	long idx, remain, size;
	unsigned long lack_size;
	int error = 0;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		printk(KERN_ERR "hackernel: kmalloc path failed!\n");
		error = -1;
		goto out;
	}

	lack_size = copy_from_user(path, pathname,
				   strnlen_user(pathname, PATH_MAX));
	if (lack_size) {
		printk(KERN_ERR
		       "hackernel: read pathname from user failed! pathname=%p\n",
		       pathname);
		error = -1;
		goto out;
	}
	printk(KERN_INFO "hackernel: path=%s\n", path);

	params = kzalloc(ARG_MAX, GFP_KERNEL);
	if (!params) {
		printk(KERN_ERR "hackernel: kmalloc params failed!\n");
		error = -1;
		goto out;
	}
	size = count(argv, MAX_ARG_STRINGS);
	p = kzalloc((size + 1) * sizeof(char *), GFP_KERNEL);


	lack_size = copy_from_user(p,argv,size * sizeof(char *));
	if(lack_size){
		printk(KERN_ERR
		       "hackernel: read path from user failed! argv=%p\n",
		       argv);
		error = -1;
		goto out;
	}

	for (idx = 0, size = 0, cursor = params; p[idx]; ++idx) {
		remain = ARG_MAX - (cursor - params);
		if (remain <= 0) {
			printk(KERN_WARNING
			       "hackernel: the parameter is too long and is truncated\n");
			break;
		}
		size = strnlen_user(p[idx], remain);
		lack_size = copy_from_user(cursor, p[idx], size);
		if (lack_size) {
			printk(KERN_ERR
			       "hackernel: read argv from user failed! argv=%p\n",
			       argv);
			break;
		}
		cursor += size;
		*(cursor - 1) = ' ';
	}

	printk(KERN_INFO "hackernel: cmd=%s\n", params);

out:
	kfree(p);
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
