/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/heartbeat.h"
#include "nlc/netlink.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <thread>
#include <unistd.h>

namespace hackernel {

static std::mutex mutex;
static std::condition_variable cv;
static bool running = false;

void stop_heartbeat() {
    mutex.lock();
    running = false;
    mutex.unlock();

    cv.notify_one();
}

int send_pid_to_kernel(int interval) {
    struct nl_msg *msg = NULL;
    pid_t tgid = getpid();

    // 仅能有一个发送心跳的线程
    if (running)
        return -EPERM;

    running = interval ? get_running_status() : 0;
    do {
        msg = alloc_hackernel_nlmsg(HACKERNEL_C_HANDSHAKE);
        nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_TGID, tgid);
        send_free_hackernel_nlmsg(msg);

        std::unique_lock<std::mutex> lock(mutex);
        cv.wait_for(lock, std::chrono::milliseconds(interval), [&]() { return !running; });
    } while (running);

    return 0;
}

int handshake_with_kernel() {
    return send_pid_to_kernel(0);
}

int start_heartbeat() {
    change_thread_name("heartbeat");
    DBG("heartbeat enter");
    int error = send_pid_to_kernel(HEARTBEAT_INTERVAL);
    DBG("heartbeat exit");
    return error;
}

int handle_heartbeat(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    int code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
    if (code) {
        ERR("handshake response code=[%d]", code);
        ERR("handshake failed. exit");
        stop_server(HACKERNEL_HEARTBEAT);
    }
    return 0;
}

}; // namespace hackernel
