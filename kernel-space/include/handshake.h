/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HACKERNEL_HANDSHAKE_H
#define HACKERNEL_HANDSHAKE_H

#include <linux/kernel.h>

enum {
	HANDSHAKE_A_UNSPEC,
	HANDSHAKE_A_STATUS_CODE,
	HANDSHAKE_A_SYS_SERVICE_TGID,
	__HANDSHAKE_A_MAX,
};
#define HANDSHAKE_A_MAX (__HANDSHAKE_A_MAX - 1)

void tgid_init(pid_t pid);
int hackernel_heartbeat_check(u32 portid);

#endif
