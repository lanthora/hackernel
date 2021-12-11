#ifndef HACKERNEL_NLSERVER_NETLINK_H
#define HACKERNEL_NLSERVER_NETLINK_H

#include "hackernel/util.h"

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

int NetlinkGetFamilyID();
struct nl_sock *NetlinkGetNlSock();
void NetlinkServerInit(void);
int NetlinkWait(void);
int NetlinkExitNotify(void);

EXTERN_C_END

#endif
