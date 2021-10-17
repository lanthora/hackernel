#include "syscall.h"

pid_t g_service_tgid;

extern u32 g_portid;

int hackernel_heartbeat_check(u32 portid)
{
	static unsigned long last = INITIAL_JIFFIES;
	const unsigned long timeout = msecs_to_jiffies(3000U);

	if (g_portid == 0)
		goto portidout;

	if (portid == g_portid)
		goto lastout;

	if (time_is_before_jiffies(last + timeout))
		goto portidout;

	return -EPERM;

portidout:
	g_portid = portid;
lastout:
	last = jiffies;
	return 0;
}

void tgid_init(pid_t pid)
{
	if (g_service_tgid == pid)
		return;
	g_service_tgid = pid;
	LOG("pid = [%d]", pid);
}
