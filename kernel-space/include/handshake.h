#ifndef HACKERNEL_HANDSHAKE_H
#define HACKERNEL_HANDSHAKE_H

#include <linux/kernel.h>

enum {
	HANDSHAKE_A_UNSPEC,
	HANDSHAKE_A_STATUS_CODE,
	HANDSHAKE_A_SYS_CALL_TABLE_HEADER,
	HANDSHAKE_A_SYS_SERVICE_TGID,
	__HANDSHAKE_A_MAX,
};
#define HANDSHAKE_A_MAX (__HANDSHAKE_A_MAX - 1)

int init_sys_call_table(u64 sys_call_table);
void init_service_tgid(pid_t pid);

#endif