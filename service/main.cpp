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
#include <signal.h>
#include <thread>
#include <unistd.h>

static int enable() {
    int error = 0;

    error = handshake();
    if (error) {
        LOG("handshake failed");
        return error;
    }

    error = enable_process_protect();
    if (error) {
        LOG("enable_process_protect failed");
        return error;
    }

    error = enable_file_protect();
    if (error) {
        LOG("enable_file_protect failed");
        return error;
    }

    return 0;
}

static int test_file() {
    int error;
    error = set_file_protect("/root/test/protect/modify-me",
                             READ_PROTECT_MASK | WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }
    error = set_file_protect("/root/test/protect", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }

    error = set_file_protect("/root/test", RENAME_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }

    error = set_file_protect("/root", RENAME_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }
    return 0;
}

static int fstab_file() {
    int error;
    error = set_file_protect("/etc/fstab", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }

    error = set_file_protect("/etc", RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }
    return 0;
}

static int startup() {
    int error;
    error = set_file_protect("/etc/systemd/system/multi-user.target.wants", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }
    error = set_file_protect("/etc/systemd/system", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }

    error = set_file_protect("/etc/systemd/system/getty.target.wants", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }

    error =
        set_file_protect("/etc/systemd/system/network-online.target.wants", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }
    return 0;
}

static int crontab(){
    int error;
    error = set_file_protect("/var/spool/cron/root", WRITE_PROTECT_MASK | RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }

    error = set_file_protect("/var/spool/cron", RENAME_PROTECT_MASK | UNLINK_PROTECT_MASK);
    if (error) {
        LOG("set_file_protect failed");
        return error;
    }
    return 0;
}

static int test() {
    int error = 0;

    error = enable();
    if (error) {
        return error;
    }

    error = test_file();
    if (error) {
        return error;
    }

    error = fstab_file();
    if (error) {
        return error;
    }

    error = startup();
    if (error) {
        return error;
    }
    error = crontab();
    if (error) {
    	return error;
    }

    return 0;
}

void sig_handler(int sig) {
    LOG("received signal, exit now");
    disable_file_protect();
    disable_process_protect();
    netlink_server_stop();
}

int main() {
    int error;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    error = netlink_server_init();
    if (error) {
        exit(1);
    }

    std::thread netlink_thread(netlink_server_start);
    std::thread test_thread(test);

    test_thread.join();
    netlink_thread.join();
    return 0;
}
