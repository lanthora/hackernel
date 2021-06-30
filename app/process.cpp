#include "command.h"
#include "util.h"

int update_process_protect_status(uint8_t status) {
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

    error = nla_put_u8(msg, HACKERNEL_A_OP_TYPE, status);
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

int enable_process_protect() { return update_process_protect_status(PROCESS_PROTECT_ENABLE); }
int disable_process_protect() { return update_process_protect_status(PROCESS_PROTECT_DISABLE); }

process_perm_t check_precess_perm(char *cmd) {
    process_perm_t perm = PROCESS_ACCEPT;
    return perm;
}

int reply_process_perm(process_perm_id_t id, process_perm_t perm) {
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

    error = nla_put_u8(msg, HACKERNEL_A_OP_TYPE, PROCESS_PROTECT_REPORT);
    if (error) {
        LOG("nla_put_u8 failed");
        goto errout;
    }

    error = nla_put_s32(msg, HACKERNEL_A_EXECVE_ID, id);
    if (error) {
        LOG("nla_put_s32 failed");
        goto errout;
    }

    error = nla_put_s32(msg, HACKERNEL_A_PERM, perm);
    if (error) {
        LOG("nla_put_s32 failed");
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
