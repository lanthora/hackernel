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

enum {
  FILE_PROTECT_UNSPEC,
  FILE_PROTECT_REPORT,
  FILE_PROTECT_ENABLE,
  FILE_PROTECT_DISABLE,
  FILE_PROTECT_SET
};

int enableFileProtect();
int disableFileProtect();
int setFileProtect(const std::string &path, file_perm_t perm);

/**
 * process protect
 */
typedef int ProcessPermId;
typedef int32_t ProcessPerm;

enum {
  PROCESS_PROTECT_UNSPEC,
  PROCESS_PROTECT_REPORT,
  PROCESS_PROTECT_ENABLE,
  PROCESS_PROTECT_DISABLE
};

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

int enableProcessProtect();
int disableProcessProtect();
ProcessPerm checkProcessPerm(char *cmd);
int replyProcessPerm(ProcessPermId id, ProcessPerm perm);

/**
 * net protect
 */
typedef uint32_t Addr;
typedef uint16_t Port;
typedef uint8_t Protocol;
typedef uint32_t Response;
typedef uint32_t PolicyId;
typedef int8_t Priority;

#define NET_POLICY_DROP 0
#define NET_POLICY_ACCEPT 1

enum {
  NET_PROTECT_UNSPEC,
  NET_PROTECT_ENABLE,
  NET_PROTECT_DISABLE,
  NET_PROTECT_INSERT,
  NET_PROTECT_DELETE,
};

/**
 * 优先级(priority)相同的情况下, 后添加的优先命中
 * 多个NetPolicy可以有相同的id, 根据id可以批量删除
 * 所有的数据都为主机序
 */
struct NetPolicy {
  PolicyId id;
  Priority priority;

  struct {
    struct {
      Addr begin;
      Addr end;
    } src;
    struct {
      Addr begin;
      Addr end;
    } dst;
  } addr;

  struct {
    struct {
      Port begin;
      Port end;
    } src;
    struct {
      Port begin;
      Port end;
    } dst;
  } port;

  struct {
    Protocol begin;
    Protocol end;
  } protocol;

  Response response;
  int flags;
};

int netPolicyInsert(const NetPolicy &policy);
int netPolicyDelete(PolicyId id);

int enableNetProtect();
int disableNetProtect(void);

#endif
