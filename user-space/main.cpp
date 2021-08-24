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
  netlinkServerStop();
}

int main() {
  int Error;

  signal(SIGINT, sigHandler);
  signal(SIGTERM, sigHandler);

  Error = netlinkServerInit();
  if (Error) {
    exit(1);
  }

  std::thread NetlinkThread(netlinkServerStart);

  handshake();
  enableProcessProtect();

  enableFileProtect();
  setFileProtect("/root/hackernel/build/nothing", ALL_FILE_PROTECT_FLAG);

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

  NetlinkThread.join();
  return 0;
}
