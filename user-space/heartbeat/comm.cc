/* SPDX-License-Identifier: GPL-2.0 */
#include "hackernel/heartbeat.h"
#include "hknl/netlink.h"
#include <chrono>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <thread>
#include <unistd.h>

namespace hackernel {

static bool running = false;

void HeartbeatExit() {
    running = false;
}

int HeartbeatHelper(int interval) {
    struct nl_msg *msg = NULL;
    pid_t tgid = getpgrp();

    // 仅能有一个发送心跳的线程
    if (running)
        return -EPERM;

    running = interval ? GlobalRunningGet() : 0;
    do {
        msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_HANDSHAKE,
                    HACKERNEL_FAMLY_VERSION);
        nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_TGID, tgid);
        nl_send_auto(NetlinkGetNlSock(), msg);
        nlmsg_free(msg);
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    } while (running);

    return 0;
}

int Handshake() {
    return HeartbeatHelper(0);
}

int HeartbeatWait() {
    ThreadNameUpdate("heartbeat");
    LOG("heartbeat enter");
    int error = HeartbeatHelper(100);
    LOG("heartbeat exit");
    return error;
}

int HeartbeatHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    int code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
    if (code) {
        ERR("handshake response code=[%d]", code);
        ERR("handshake failed. exit");
        Shutdown();
    }

    return 0;
}

}; // namespace hackernel
