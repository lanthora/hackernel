#include "syscall.h"
#include "file.h"
#include "perm.h"
#include "process.h"
#include "util.h"
#include <asm/special_insns.h>
#include <net/net_namespace.h>

sys_call_ptr_t *g_sys_call_table = NULL;

int init_sys_call_table(u64 sys_call_table)
{
	if (g_sys_call_table)
		return -1;
	if (!sys_call_table)
		return -1;
	g_sys_call_table = (sys_call_ptr_t *)sys_call_table;
	return 0;
}

int enable_process_protect(void)
{
	process_perm_init();
	REG_HOOK(execve);
	REG_HOOK(execveat);
	return 0;
}

int disable_process_protect(void)
{
	UNREG_HOOK(execve);
	UNREG_HOOK(execveat);
	process_perm_destory();
	return 0;
}

int enable_file_protect(void)
{
	file_perm_init();
	REG_HOOK(open);
	REG_HOOK(openat);
	REG_HOOK(unlink);
	REG_HOOK(unlinkat);
	REG_HOOK(rename);
	REG_HOOK(renameat);
	REG_HOOK(renameat2);
	REG_HOOK(mkdir);
	REG_HOOK(mkdirat);
	REG_HOOK(rmdir);
	REG_HOOK(link);
	REG_HOOK(linkat);
	REG_HOOK(symlink);
	REG_HOOK(symlinkat);
	REG_HOOK(mknod);
	REG_HOOK(mknodat);
	return 0;
}

int disable_file_protect(void)
{
	UNREG_HOOK(open);
	UNREG_HOOK(openat);
	UNREG_HOOK(unlink);
	UNREG_HOOK(unlinkat);
	UNREG_HOOK(rename);
	UNREG_HOOK(renameat);
	UNREG_HOOK(renameat2);
	UNREG_HOOK(mkdir);
	UNREG_HOOK(mkdirat);
	UNREG_HOOK(rmdir);
	UNREG_HOOK(link);
	UNREG_HOOK(linkat);
	UNREG_HOOK(symlink);
	UNREG_HOOK(symlinkat);
	UNREG_HOOK(mknod);
	UNREG_HOOK(mknodat);
	file_perm_destory();
	return 0;
}

static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;
	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

void enable_write_protection(void)
{
	write_cr0_forced(read_cr0() | 0x00010000);
}

void disable_write_protection(void)
{
	write_cr0_forced(read_cr0() & ~0x00010000);
}
