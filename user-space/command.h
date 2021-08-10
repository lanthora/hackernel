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
typedef uint32_t addr_t;
typedef uint16_t port_t;
typedef uint8_t protocol_t;
typedef uint32_t response_t;
typedef uint32_t policy_id_t;
typedef int8_t priority_t;

#define NET_POLICY_DROP 0
#define NET_POLICY_ACCEPT 1

enum
{
    NET_PROTECT_UNSPEC,
    NET_PROTECT_ENABLE,
    NET_PROTECT_DISABLE,
    NET_PROTECT_INSERT,
    NET_PROTECT_DELETE,
};

/**
 * 优先级(priority)相同的情况下, 后添加的优先命中
 * 多个net_policy_t可以有相同的id, 根据id可以批量删除
 * 所有的数据都为主机序
 */
struct net_policy_t {
    policy_id_t id;
    priority_t priority;

    struct {
        struct {
            addr_t begin;
            addr_t end;
        } src;
        struct {
            addr_t begin;
            addr_t end;
        } dst;
    } addr;

    struct {
        struct {
            port_t begin;
            port_t end;
        } src;
        struct {
            port_t begin;
            port_t end;
        } dst;
    } port;

    struct {
        protocol_t begin;
        protocol_t end;
    } protocol;

    response_t response;
    int flags;
};

int net_policy_insert(const net_policy_t &policy);
int net_policy_delete(policy_id_t id);

int enable_net_protect();
int disable_net_protect(void);

#endif
