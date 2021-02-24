#include "syscall.h"
#include "sys_execve.h"
#include <asm/special_insns.h>
#include <net/net_namespace.h>

sys_call_ptr_t *g_sys_call_table = NULL;

int init_sys_call_table(u64 sys_call_table)
{
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

void enable_write_protection(void)
{
}

void disable_write_protection(void)
{
}
