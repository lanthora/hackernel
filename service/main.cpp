#include "command.h"
#include "handler.h"
#include "netlink.h"
#include "syscall.h"
#include "util.h"
#include <iostream>
#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>
#include <thread>
#include <unistd.h>

int main() {
    int error = 0;
    std::thread netlink_thread(netlink_server_start);

    error = handshake();
    if (error) {
        LOG("handshake failed");
        return -1;
    }

    error = enable_process_protect();
    if (error) {
        LOG("enable_process_protect failed");
        return -1;
    }

    error = enable_file_protect();
    if (error) {
        LOG("enable_file_protect failed");
        return -1;
    }

    error = set_file_protect("/root/test/protect/modify-me", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return -1;
    }

    sleep(1);
    netlink_server_stop();
    netlink_thread.join();
    return 0;
}
