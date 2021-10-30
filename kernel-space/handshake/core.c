#include "syscall.h"
#include "watchdog.h"

pid_t g_service_tgid;
extern u32 g_portid;

int hackernel_heartbeat_check(u32 portid)
{
	if (portid == g_portid)
		goto time_update;

	if (conn_check_living())
		return -EPERM;

	g_portid = portid;

time_update:
	conn_check_set_alive();
	return 0;
}

void tgid_init(pid_t pid)
{
	if (g_service_tgid == pid)
		return;
	g_service_tgid = pid;
}
