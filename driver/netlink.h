#ifndef HACKERNEL_NETLINK_KERNEL_SPACE
#define HACKERNEL_NETLINK_KERNEL_SPACE

#define HACKERNEL_FAMLY_NAME "HACKERNEL"
#define HACKERNEL_FAMLY_VERSION 1

enum {
	HACKERNEL_A_UNSPEC,
	HACKERNEL_A_MSG,
	HACKERNEL_A_SYS_CALL_TABLE,
	__HACKERNEL_A_MAX,
};
#define HACKERNEL_A_MAX (__HACKERNEL_A_MAX - 1)

enum {
	HACKERNEL_C_UNSPEC,
	HACKERNEL_C_HANDSHAKE,
	__HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

struct handshake_data {
	int status;
	char msg[64];
};

void netlink_kernel_start(void);
void netlink_kernel_stop(void);

#endif