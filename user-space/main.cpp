#include "command.h"
#include "handler.h"
#include "netlink.h"
#include "syscall.h"
#include "util.h"
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
    enable_net_protect();
    set_file_protect("/root/hackernel/build/nothing", ALL_FILE_PROTECT_FLAG);

    netlink_thread.join();
    return 0;
}
