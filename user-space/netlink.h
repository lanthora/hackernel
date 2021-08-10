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
    HANDSHAKE_A_UNSPEC,
    HANDSHAKE_A_STATUS_CODE,
    HANDSHAKE_A_SYS_CALL_TABLE_HEADER,
    __HANDSHAKE_A_MAX,
};
#define HANDSHAKE_A_MAX (__HANDSHAKE_A_MAX - 1)

enum
{
    HACKERNEL_C_UNSPEC,
    HACKERNEL_C_HANDSHAKE,
    HACKERNEL_C_PROCESS_PROTECT,
    HACKERNEL_C_FILE_PROTECT,
    HACKERNEL_C_NET_PROTECT,
    __HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

enum
{
    FILE_A_UNSPEC,
    FILE_A_STATUS_CODE,
    FILE_A_OP_TYPE,
    FILE_A_NAME,
    FILE_A_PERM,
    __FILE_A_MAX,
};
#define FILE_A_MAX (__FILE_A_MAX - 1)

enum
{
    PROCESS_A_UNSPEC,
    PROCESS_A_STATUS_CODE,
    PROCESS_A_OP_TYPE,
    PROCESS_A_NAME,
    PROCESS_A_PERM,
    PROCESS_A_ID,
    __PROCESS_A_MAX,
};
#define PROCESS_A_MAX (__PROCESS_A_MAX - 1)

enum
{
    NET_A_UNSPEC,
    NET_A_STATUS_CODE,
    NET_A_OP_TYPE,
    NET_A_ID,
    NET_A_PRIORITY,

    NET_A_ADDR_SRC_BEGIN,
    NET_A_ADDR_SRC_END,
    NET_A_ADDR_DST_BEGIN,
    NET_A_ADDR_DST_END,

    NET_A_PORT_SRC_BEGIN,
    NET_A_PORT_SRC_END,
    NET_A_PORT_DST_BEGIN,
    NET_A_PORT_DST_END,

    NET_A_PROTOCOL_BEGIN,
    NET_A_PROTOCOL_END,

    NET_A_RESPONSE,

    NET_A_FLAGS,

    __NET_A_MAX,
};
#define NET_A_MAX (__NET_A_MAX - 1)

int netlink_server_init(void);
int netlink_server_start(void);
int netlink_server_stop(void);

extern struct nl_sock *nlsock;
extern int famid;

#ifdef __cplusplus
}
#endif

#endif
