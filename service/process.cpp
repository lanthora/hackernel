#include "command.h"
#include "util.h"

int enable_process_protect() {
    int error;
    struct nl_msg *msg = NULL;
    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nl_send_auto(nlsock, msg);

    if (error < 0) {
        LOG("nl_send_auto failed error=[%d]", error);
        goto errout;
    }

    return 0;

errout:
    nlmsg_free(msg);
    return -1;
}