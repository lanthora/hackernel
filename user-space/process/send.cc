
#include "hackernel/ipc.h"
#include "hackernel/process.h"
#include "hknl/netlink.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

namespace hackernel {

int ProcProtectStatusUpdate(int32_t session, uint8_t status) {
    struct nl_msg *message = NULL;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_u8(message, PROCESS_A_OP_TYPE, status);

    nl_send_auto(NetlinkGetNlSock(), message);
    nlmsg_free(message);
    return 0;
}

int ProcProtectEnable() {
    return ProcProtectEnable(SYSTEM_SESSION_ID);
}
int ProcProtectDisable() {
    return ProcProtectDisable(SYSTEM_SESSION_ID);
}

int ProcProtectEnable(int32_t session) {
    return ProcProtectStatusUpdate(session, PROCESS_PROTECT_ENABLE);
}
int ProcProtectDisable(int32_t session) {
    return ProcProtectStatusUpdate(session, PROCESS_PROTECT_DISABLE);
}

ProcPerm ProcPermCheck(char *cmd) {
    ProcPerm perm = PROCESS_ACCEPT;
    return perm;
}

int ProcPermReply(ProcPermID id, ProcPerm perm) {
    struct nl_msg *message = NULL;

    message = nlmsg_alloc();
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, NetlinkGetFamilyID(), 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT,
                HACKERNEL_FAMLY_VERSION);
    nla_put_u8(message, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
    nla_put_s32(message, PROCESS_A_ID, id);
    nla_put_s32(message, PROCESS_A_PERM, perm);
    nl_send_auto(NetlinkGetNlSock(), message);
    nlmsg_free(message);
    return 0;
}

}; // namespace hackernel
