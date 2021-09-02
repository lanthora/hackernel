#include "syscall.h"

sys_call_ptr_t *g_sys_call_table = NULL;
pid_t service_pid;
int init_sys_call_table(u64 sys_call_table)
{
	if (g_sys_call_table)
		return -1;
	if (!sys_call_table)
		return -1;
	g_sys_call_table = (sys_call_ptr_t *)sys_call_table;
	return 0;
}

void init_service_pid(pid_t pid)
{
	service_pid = pid;
}
