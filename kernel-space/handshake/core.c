#include "syscall.h"

pid_t g_service_tgid;

extern u32 g_portid;

int hackernel_heartbeat_check(u32 portid)
{
	static unsigned long last = 0UL;
	const unsigned long timeout = msecs_to_jiffies(3000U);

	if (portid != g_portid && time_is_before_eq_jiffies(last + timeout))
		return -EPERM;

	last = jiffies;
	g_portid = portid;
	return 0;
}

void init_tgid(pid_t pid)
{
	if (g_service_tgid == pid)
		return;
	g_service_tgid = pid;
	LOG("pid = [%d]", pid);
}
