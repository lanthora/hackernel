#include "syscall.h"

sys_call_ptr_t *g_sys_call_table = NULL;
pid_t g_service_tgid;

extern u32 g_portid;

int hackernel_heartbeat_check(u32 portid)
{
	static u64 last = 0UL;
	const unsigned int timeout = 3000U;

	if (portid != g_portid &&
	    jiffies_delta_to_msecs(get_jiffies_64() - last) < timeout)
		return -EPERM;

	last = get_jiffies_64();
	g_portid = portid;
	return 0;
}

int init_sys_call_table(u64 sys_call_table)
{
	if (g_sys_call_table)
		return -EPERM;
	if (!sys_call_table)
		return -EINVAL;
	g_sys_call_table = (sys_call_ptr_t *)sys_call_table;
	return 0;
}

void init_service_tgid(pid_t pid)
{
	g_service_tgid = pid;
	LOG("pid = [%d]", pid);
}
