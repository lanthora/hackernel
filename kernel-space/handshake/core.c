#include "syscall.h"

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

void init_tgid(pid_t pid)
{
	if (g_service_tgid == pid)
		return;
	g_service_tgid = pid;
	LOG("pid = [%d]", pid);
}
