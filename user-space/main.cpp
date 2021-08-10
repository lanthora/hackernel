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

void exit_sig_handler(int sig) {
    LOG("received signal, exit now");
    disable_file_protect();
    disable_process_protect();
    disable_net_protect();
    netlink_server_stop();
}

int main() {
    int error;

    signal(SIGINT, exit_sig_handler);
    signal(SIGTERM, exit_sig_handler);

    error = netlink_server_init();
    if (error) {
        exit(1);
    }

    std::thread netlink_thread(netlink_server_start);

    handshake();
    enable_process_protect();

    enable_file_protect();
    set_file_protect("/root/hackernel/build/nothing", ALL_FILE_PROTECT_FLAG);

    enable_net_protect();
    net_policy_t policy;

    policy.addr.src.begin = ntohl(inet_addr("127.0.0.1"));
    policy.addr.src.end = ntohl(inet_addr("127.0.0.1"));
    policy.addr.dst.begin = ntohl(inet_addr("127.0.0.1"));
    policy.addr.dst.end = ntohl(inet_addr("127.0.0.1"));
    policy.port.src.begin = 0;
    policy.port.src.end = UINT16_MAX;

    // ssh
    policy.port.dst.begin = 22;
    policy.port.dst.end = 22;
    // tcp
    policy.protocol.begin = 6;
    policy.protocol.end = 6;

    policy.id = 0;
    policy.enabled = 1;
    policy.priority = 0;
    policy.response = NET_POLICY_DROP;
    net_policy_insert(policy);

    policy.addr.src.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.src.end = ntohl(inet_addr("255.255.255.255"));
    policy.addr.dst.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.dst.end = ntohl(inet_addr("255.255.255.255"));
    policy.port.dst.begin = 0;
    policy.port.dst.end = UINT16_MAX;
    policy.protocol.begin = 0;
    policy.protocol.end = UINT8_MAX;
    policy.response = NET_POLICY_ACCEPT;
    policy.priority = -1;
    policy.id = 5;
    net_policy_insert(policy);
    net_policy_delete(5);

    netlink_thread.join();
    return 0;
}
