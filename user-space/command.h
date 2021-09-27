#ifndef HACKERNEL_COMMAND_H
#define HACKERNEL_COMMAND_H

#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#include <cstdint>
#include <string>

#include "netlink.h"

int Handshake();
int Heartbeat();
void StopHeartbeat();

typedef int32_t FilePerm;

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

int EnableFileProtect();
int DisableFileProtect();
int SetFileProtect(const std::string &path, FilePerm perm);

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

int EnableProcessProtect();
int DisableProcessProtect();
ProcessPerm CheckProcessPerm(char *cmd);
int ReplyProcessPerm(ProcessPermId id, ProcessPerm perm);

typedef uint32_t NetAddr;
typedef uint16_t NetPort;
typedef uint8_t NetProtocol;
typedef uint32_t NetResponse;
typedef uint32_t NetPolicyId;
typedef int8_t NetPriority;

#define NET_POLICY_DROP 0
#define NET_POLICY_ACCEPT 1

enum {
  NET_PROTECT_UNSPEC,
  NET_PROTECT_ENABLE,
  NET_PROTECT_DISABLE,
  NET_PROTECT_INSERT,
  NET_PROTECT_DELETE,
};

// 优先级(Priority)相同的情况下, 后添加的优先命中,多个NetPolicy可以有相同的id,
// 根据Id可以批量删除 所有的数据都为主机序
struct NetPolicy {
  NetPolicyId id;
  NetPriority priority;

  struct {
    struct {
      NetAddr begin;
      NetAddr end;
    } src;
    struct {
      NetAddr begin;
      NetAddr end;
    } dst;
  } addr;

  struct {
    struct {
      NetPort begin;
      NetPort end;
    } src;
    struct {
      NetPort begin;
      NetPort end;
    } dst;
  } port;

  struct {
    NetProtocol begin;
    NetProtocol end;
  } protocol;

  NetResponse response;
  int flags;
};

int NetPolicyInsert(const NetPolicy &policy);
int NetPolicyDelete(NetPolicyId id);

int EnableNetProtect();
int DisableNetProtect(void);

#endif
