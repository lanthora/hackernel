#include "command.h"
#include "util.h"

int enable_file_protect() {
    int error;
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nla_put_u32(msg, HACKERNEL_A_CODE, FILE_PROTECT_ENABLE);
    if (error) {
        LOG("nla_put_s32 failed");
        goto errout;
    }

    error = nl_send_auto(nlsock, msg);
    nlmsg_free(msg);
    if (error < 0) {
        LOG("nl_send_auto failed error=[%d]", error);
        goto errout;
    }

    return 0;

errout:
    nlmsg_free(msg);
    return -1;
}

int set_file_protect(const std::string &path, perm_t perm) {
    int error;
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nla_put_s32(msg, HACKERNEL_A_CODE, FILE_PROTECT_SET);
    if (error) {
        LOG("nla_put_s32 failed");
        goto errout;
    }

    error = nla_put_string(msg, HACKERNEL_A_NAME, path.data());
    if (error) {
        LOG("nla_put_s32 failed");
        goto errout;
    }
    error = nla_put_u32(msg, HACKERNEL_A_PERM, perm);
    if (error) {
        LOG("nla_put_u32 failed");
        goto errout;
    }
    error = nl_send_auto(nlsock, msg);
    nlmsg_free(msg);
    if (error < 0) {
        LOG("nl_send_auto failed [%d]", error);
        goto errout;
    }

    return 0;

errout:
    nlmsg_free(msg);
    return -1;
}
