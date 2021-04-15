#include "sys_execve.h"
#include "syscall.h"
#include "util.h"
#include <linux/syscalls.h>

static sys_call_ptr_t real_execve = NULL;

static int custom_execve_pretty(const char *pathname, const char *const *argv,
			const char *const *envp)
{
	int i;
	int argv_cout;
	int envp_cout;

	if(!strcmp(pathname,"/usr/bin/dmesg"))
		return 0;
	if(!strcmp(pathname,"/usr/bin/sleep"))
		return 0;

	argv_cout = count_strings(argv);
	envp_cout = count_strings(envp);

	printk(KERN_INFO "hackernel: pathname=%s\n", pathname);

	for (i = 1; i < argv_cout; ++i) {
		printk(KERN_INFO "hackernel: argv[%d]=%s\n", i, argv[i]);
	}

	for (i = 0; i < envp_cout; ++i) {
		if(strncmp(envp[i],"PWD=",4))
			continue;
		printk(KERN_INFO "hackernel: %s\n", envp[i]);
		break;
	}
	return 0;
}

asmlinkage u64 custom_execve(const struct pt_regs *regs)
{
	const char *pathname = (const char *)regs->di;
	const char *const *argv = (const char *const *)regs->si;
	const char *const *envp = (const char *const *)regs->dx;
	if(custom_execve_pretty(pathname, argv, envp))
		return -EPERM;
	return real_execve(regs);
}

int replace_execve(void)
{
	if (!g_sys_call_table) {
		printk(KERN_ERR "hackernel: g_sys_call_table must be initialized before calling replace_execve\n");
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
