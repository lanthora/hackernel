#include "sys_execve.h"
#include "syscall.h"
#include "util.h"
#include <linux/syscalls.h>

static sys_call_ptr_t real_execve = NULL;

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
// 在 include/linux/compat_sys_execve 中存在另一个系统调用的实现
static int sys_evecve(const char *pathname, const char *const *argv,
		      const char *const *envp)
{
	int i;
	int argv_cout;
	int envp_cout;

	printk(KERN_DEBUG "hackernel: pathname=%s\n", pathname);

	// 这两个函数复杂度较高，可能会影响系统运行效率
	argv_cout = count_strings(argv);
	envp_cout = count_strings(envp);

	for (i = 1; i < argv_cout; ++i) {
		printk(KERN_DEBUG "hackernel: argv[%d]=%s\n", i, argv[i]);
	}

	for (i = 0; i < envp_cout; ++i) {
		printk(KERN_DEBUG "hackernel: %s\n", envp[i]);
	}

	return 0;
}

asmlinkage u64 raw_sys_execve(const struct pt_regs *regs)
{
	const char *pathname = (const char *)regs->di;
	const char *const *argv = (const char *const *)regs->si;
	const char *const *envp = (const char *const *)regs->dx;
	static atomic_t running_execve_cnt = ATOMIC_INIT(0);

	// 检查正在执行的sys_evecve系统调用的个数
	int cnt = atomic_inc_return(&running_execve_cnt);
	printk(KERN_DEBUG "hackernel: running execve cnt=%d\n", cnt);
	if (sys_evecve(pathname, argv, envp))
		return -EPERM;

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
		printk(KERN_INFO "hackernel: restore_execve before replace\n");
		return 0;
	}
	disable_write_protection();
	g_sys_call_table[__NR_execve] = real_execve;
	enable_write_protection();
	return 0;
}
