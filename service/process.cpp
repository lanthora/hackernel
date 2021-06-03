#include "command.h"
#include "util.h"

int enable_process_protect() {
    int error = 0;
    struct nl_msg *msg = NULL;
    int size;

    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        error = -ENOMEM;
        goto errout;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nla_put_u8(msg, HACKERNEL_A_TYPE, PROCESS_PROTECT_ENABLE);
    if (error) {
        LOG("nla_put_u8 failed");
        goto errout;
    }
    size = nl_send_auto(nlsock, msg);
    if (size < 0) {
        LOG("nl_send_auto failed error=[%d]", error);
        error = size;
        goto errout;
    }

errout:
    nlmsg_free(msg);
    return error;
}