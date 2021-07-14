#ifndef HACKERNEL_NETLINK_USER_SPACE
#define HACKERNEL_NETLINK_USER_SPACE

#ifdef __cplusplus
extern "C" {
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define HACKERNEL_FAMLY_NAME "HACKERNEL"

#define HACKERNEL_FAMLY_VERSION 1

enum
{
    HACKERNEL_A_UNSPEC,
    HACKERNEL_A_STATUS_CODE,
    HACKERNEL_A_OP_TYPE,
    HACKERNEL_A_SYS_CALL_TABLE_HEADER,
    HACKERNEL_A_NAME,
    HACKERNEL_A_PERM,
    HACKERNEL_A_EXECVE_ID,
    __HACKERNEL_A_MAX,
};
#define HACKERNEL_A_MAX (__HACKERNEL_A_MAX - 1)

enum
{
    HACKERNEL_C_UNSPEC,
    HACKERNEL_C_HANDSHAKE,
    HACKERNEL_C_PROCESS_PROTECT,
    HACKERNEL_C_FILE_PROTECT,
    __HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

int netlink_server_init(void);
int netlink_server_start(void);
int netlink_server_stop(void);

extern struct nl_sock *nlsock;
extern int famid;

#ifdef __cplusplus
}
#endif

#endif
