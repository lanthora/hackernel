/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/heartbeat.h"
#include "hknl/netlink.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <thread>
#include <unistd.h>

namespace hackernel {

static std::mutex exit_mutex;
static std::condition_variable exit_signal;
static bool running = false;

void HeartbeatExit() {
    running = false;
    exit_signal.notify_one();
}

int HeartbeatHelper(int interval) {
    struct nl_msg *msg = NULL;
    pid_t tgid = getpgrp();

    // 仅能有一个发送心跳的线程
    if (running)
        return -EPERM;

    running = interval ? RUNNING() : 0;
    do {
        msg = NetlinkMsgAlloc(HACKERNEL_C_HANDSHAKE);
        nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_TGID, tgid);
        NetlinkSend(msg);

        std::unique_lock<std::mutex> lock(exit_mutex);
        exit_signal.wait_for(lock, std::chrono::milliseconds(running ? interval : 0));
    } while (running);

    return 0;
}

int Handshake() {
    return HeartbeatHelper(0);
}

int HeartbeatWait() {
    ThreadNameUpdate("heartbeat");
    DBG("heartbeat enter");
    const int heartbeat_interval = 1000;
    int error = HeartbeatHelper(heartbeat_interval);
    DBG("heartbeat exit");
    return error;
}

int HeartbeatHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    int code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
    if (code) {
        ERR("handshake response code=[%d]", code);
        ERR("handshake failed. exit");
        SHUTDOWN(HACKERNEL_HEARTBEAT);
    }

    return 0;
}

}; // namespace hackernel
