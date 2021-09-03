#include "command.h"
#include "handler.h"
#include "netlink.h"
#include "syscall.h"
#include "util.h"
#include <arpa/inet.h>
#include <iostream>
#include <limits>
#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>
#include <signal.h>
#include <thread>
#include <unistd.h>

void sigHandler(int sig) {
  LOG("received signal, exit now");
  disableFileProtect();
  disableProcessProtect();
  disableNetProtect();
  stopHeartbeat();
  stopNetlinkServer();
}

#define PROCESS_PROTECT 1
#define FILE_PROTECT 1
#define NET_PROTECT 1

int main() {
  int Error;

  signal(SIGINT, sigHandler);
  signal(SIGTERM, sigHandler);

  Error = initNetlinkServer();
  if (Error) {
    exit(1);
  }

  std::thread NetlinkThread(startNetlinkServer);

  handshake();

  std::thread HeartbeatThread(heartbeat);

#if PROCESS_PROTECT
  enableProcessProtect();
#endif

#if FILE_PROTECT
  enableFileProtect();
  setFileProtect("/etc/fstab", ALL_FILE_PROTECT_FLAG - READ_PROTECT_FLAG);
  setFileProtect("/boot/grub/grub.cfg", ALL_FILE_PROTECT_FLAG);
  setFileProtect("/etc/host.conf", ALL_FILE_PROTECT_FLAG - READ_PROTECT_FLAG);
#endif

#if NET_PROTECT
  enableNetProtect();

  NetPolicy policy;
  policy.Addr.Src.Begin = ntohl(inet_addr("127.0.0.1"));
  policy.Addr.Src.End = ntohl(inet_addr("127.0.0.1"));
  policy.Addr.Dst.Begin = ntohl(inet_addr("127.0.0.1"));
  policy.Addr.Dst.End = ntohl(inet_addr("127.0.0.1"));

  // ssh
  policy.Port.Src.Begin = 0;
  policy.Port.Src.End = UINT16_MAX;
  policy.Port.Dst.Begin = 22;
  policy.Port.Dst.End = 22;
  // tcp
  policy.Protocol.Begin = 6;
  policy.Protocol.End = 6;

  policy.Id = 0;
  policy.Flags = 1 | 2;
  policy.Priority = 0;
  policy.Response = NET_POLICY_DROP;
  netPolicyInsert(policy);
#endif

  NetlinkThread.join();
  HeartbeatThread.join();
  return 0;
}
