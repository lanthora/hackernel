/* SPDX-License-Identifier: GPL-2.0-only */
#include "handshake.h"
#include "syscall.h"
#include "watchdog.h"

pid_t hackernel_tgid;
extern struct net *hackernel_net;
extern u32 hackernel_portid;

int hackernel_user_check(struct genl_info *info)
{
	if (info->snd_portid != hackernel_portid)
		return -EPERM;

	if (genl_info_net(info) != hackernel_net)
		return -EPERM;
	return 0;
}

int hackernel_heartbeat_check(struct genl_info *info)
{
	if (!conn_check_living())
		goto update;

	if (hackernel_user_check(info))
		return -EPERM;

update:
	hackernel_net = genl_info_net(info);
	hackernel_portid = info->snd_portid;
	conn_check_set_alive();
	return 0;
}

bool hackernel_trusted_proccess(void)
{
	return current->tgid == hackernel_tgid;
}

void inline tgid_init(pid_t pid)
{
	hackernel_tgid = pid;
}
