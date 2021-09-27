#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>
#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <limits>
#include <thread>

#include "command.h"
#include "handler.h"
#include "netlink.h"
#include "syscall.h"
#include "util.h"

void SigHandler(int sig) {
  LOG("received signal, exit now");
  DisableFileProtect();
  DisableProcessProtect();
  DisableNetProtect();
  StopHeartbeat();
  StopNetlinkServer();
}

#define PROCESS_PROTECT 1
#define FILE_PROTECT 1
#define NET_PROTECT 1

int main() {
  int error;

  signal(SIGINT, SigHandler);
  signal(SIGTERM, SigHandler);

  error = InitNetlinkServer();
  if (error) {
    LOG("init netlink failed. exit");
    exit(1);
  }

  std::thread netlink_thread(StartNetlinkServer);

  Handshake();

  std::thread heartbeat_thread(Heartbeat);

#if PROCESS_PROTECT
  EnableProcessProtect();
#endif

#if FILE_PROTECT
  EnableFileProtect();
  SetFileProtect("/etc/fstab", ALL_FILE_PROTECT_FLAG - READ_PROTECT_FLAG);
  SetFileProtect("/boot/grub/grub.cfg", ALL_FILE_PROTECT_FLAG);
  SetFileProtect("/etc/host.conf", ALL_FILE_PROTECT_FLAG - READ_PROTECT_FLAG);
#endif

#if NET_PROTECT
  EnableNetProtect();

  NetPolicy policy;
  policy.addr.src.begin = ntohl(inet_addr("127.0.0.1"));
  policy.addr.src.end = ntohl(inet_addr("127.0.0.1"));
  policy.addr.dst.begin = ntohl(inet_addr("127.0.0.1"));
  policy.addr.dst.end = ntohl(inet_addr("127.0.0.1"));

  // ssh
  policy.port.src.begin = 0;
  policy.port.src.end = UINT16_MAX;
  policy.port.dst.begin = 22;
  policy.port.dst.end = 22;
  // tcp
  policy.protocol.begin = 6;
  policy.protocol.end = 6;

  policy.id = 0;
  policy.flags = 1 | 2;
  policy.priority = 0;
  policy.response = NET_POLICY_DROP;
  NetPolicyInsert(policy);
#endif

  netlink_thread.join();
  heartbeat_thread.join();
  return 0;
}
