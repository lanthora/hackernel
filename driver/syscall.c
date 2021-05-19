#include "syscall.h"
#include "sys_execve.h"
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

void replace_sys_call(void)
{
	int error;
	error = replace_execve();
	if (error) {
	}
}

void restore_sys_call(void)
{
	int error;
	error = restore_execve();
	if (error) {
	}
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
