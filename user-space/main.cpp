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

void exitSigHandler(int sig) {
  LOG("received signal, exit now");
  disableFileProtect();
  disableProcessProtect();
  disableNetProtect();
  netlinkServerStop();
}

int main() {
  int Error;

  signal(SIGINT, exitSigHandler);
  signal(SIGTERM, exitSigHandler);

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
  netPolicyInsert(policy);

  NetlinkThread.join();
  return 0;
}
