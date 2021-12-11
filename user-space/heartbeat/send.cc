#include "hackernel/heartbeat.h"
#include "hknl/netlink.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <unistd.h>

namespace hackernel {

static int running = 0;

void HeartbeatExitNotify() {
    running = 0;
}

int HeartbeatHelper(int interval) {
    struct nl_msg *msg = NULL;
    pid_t tgid = getpgrp();

    // 仅能有一个发送心跳的线程
    if (running)
        return -1;

    running = interval;
    do {
        msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_HANDSHAKE,
                    HACKERNEL_FAMLY_VERSION);
        nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_TGID, tgid);
        nl_send_auto(NetlinkGetNlSock(), msg);
        nlmsg_free(msg);
        sleep(interval);
    } while (running);

    return 0;
}

int Handshake() {
    return HeartbeatHelper(0);
}

int HeartbeatWait() {
    return HeartbeatHelper(1);
}

}; // namespace hackernel
