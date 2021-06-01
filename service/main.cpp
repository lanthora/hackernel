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

static void test() {
    int error = 0;
    while (!famid)
        ;

    error = handshake();
    if (error) {
        LOG("handshake failed");
        return;
    }

    error = enable_process_protect();
    if (error) {
        LOG("enable_process_protect failed");
        return;
    }

    error = enable_file_protect();
    if (error) {
        LOG("enable_file_protect failed");
        return;
    }

    error = set_file_protect("/root/test/protect/modify-me", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return;
    }

    error = set_file_protect("/root/test/protect", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return;
    }

    error = set_file_protect("/root/test", RENAME_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return;
    }

    error = set_file_protect("/root", RENAME_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return;
    }
}

int main() {
    std::thread netlink_thread(netlink_server_start);
    std::thread test_thread(test);
    test_thread.join();
    sleep(1);
    netlink_server_stop();
    netlink_thread.join();
    return 0;
}
