#include "syscall.h"
#include "watchdog.h"

pid_t g_service_tgid;
extern u32 g_portid;

int hackernel_heartbeat_check(u32 portid)
{
	if (portid != g_portid && conn_check_living())
		return -EPERM;

	g_portid = portid;
	conn_check_set_alive();
	return 0;
}

void inline tgid_init(pid_t pid)
{
	g_service_tgid = pid;
}
