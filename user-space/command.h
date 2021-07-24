#ifndef HACKERNEL_COMMAND_H
#define HACKERNEL_COMMAND_H
#include "netlink.h"
#include <cstdint>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <string>

/**
 * handshake
 */
int handshake();

/**
 * file protect
 */
typedef int32_t file_perm_t;

#define READ_PROTECT_FLAG 1
#define WRITE_PROTECT_FLAG 2
#define UNLINK_PROTECT_FLAG 4
#define RENAME_PROTECT_FLAG 8
#define ALL_FILE_PROTECT_FLAG 15

enum
{
    FILE_PROTECT_UNSPEC,
    FILE_PROTECT_REPORT,
    FILE_PROTECT_ENABLE,
    FILE_PROTECT_DISABLE,
    FILE_PROTECT_SET
};

int enable_file_protect();
int disable_file_protect();
int set_file_protect(const std::string &path, file_perm_t perm);

/**
 * process protect
 */
typedef int process_perm_id_t;
typedef int32_t process_perm_t;

enum
{
    PROCESS_PROTECT_UNSPEC,
    PROCESS_PROTECT_REPORT,
    PROCESS_PROTECT_ENABLE,
    PROCESS_PROTECT_DISABLE
};

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

int enable_process_protect();
int disable_process_protect();
process_perm_t check_precess_perm(char *cmd);
int reply_process_perm(process_perm_id_t id, process_perm_t perm);

/**
 * net protect
 */
typedef uint16_t net_port_t;
typedef uint16_t net_port_range_t;
typedef int32_t net_perm_t;

#define TCP_IN_FLAG (1 << 0)
#define TCP_OUT_FLAG (1 << 1)
#define UDP_IN_FLAG (1 << 2)
#define UDP_OUT_FLAG (1 << 3)
#define ALL_NET_PROTECT_FLAG (TCP_IN_FLAG | TCP_OUT_FLAG | UDP_IN_FLAG | UDP_OUT_FLAG)

#define TCP_IN_MASK (1 << 4)
#define TCP_OUT_MASK (1 << 5)
#define UDP_IN_MASK (1 << 6)
#define UDP_OUT_MASK (1 << 7)
#define ALL_NET_PROTECT_MASK (TCP_IN_MASK | TCP_OUT_MASK | UDP_IN_MASK | UDP_OUT_MASK)

enum
{
    NET_PROTECT_UNSPEC,
    NET_PROTECT_REPORT,
    NET_PROTECT_ENABLE,
    NET_PROTECT_DISABLE,
    NET_PROTECT_SET
};

int enable_net_protect();
int disable_net_protect();

#endif
