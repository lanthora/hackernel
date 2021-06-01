#include "command.h"
#include "util.h"

int enable_process_protect() {
    int error;
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        return -1;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nl_send_sync(nlsock, msg);
    if (error) {
        LOG("nl_send_sync failed error=[%d]",error);
        return -1;
    }

    return 0;
}