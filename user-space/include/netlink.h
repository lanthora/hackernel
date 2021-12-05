#ifndef HACKERNEL_NETLINK_USER_SPACE
#define HACKERNEL_NETLINK_USER_SPACE

#include "util.h"

EXTERN_C_BEGIN

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define HACKERNEL_FAMLY_NAME "HACKERNEL"

#define HACKERNEL_FAMLY_VERSION 1

enum {
    HACKERNEL_C_UNSPEC,
    HACKERNEL_C_HANDSHAKE,
    HACKERNEL_C_PROCESS_PROTECT,
    HACKERNEL_C_FILE_PROTECT,
    HACKERNEL_C_NET_PROTECT,
    __HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

extern struct nl_sock *g_nl_sock;
extern int g_fam_id;

// 初始化用来接收内核消息的服务,初始化失败退出进程
// 初始化成功后内核就有能力把消息放到缓冲区
void NetlinkServerInit(void);
int NetlinkServerStart(void);
int NetlinkServerStop(void);

EXTERN_C_END

#endif
