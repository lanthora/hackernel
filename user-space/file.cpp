#include "command.h"
#include "util.h"

static int update_file_protect_status(uint8_t status) {
    int error = 0;
    struct nl_msg *msg;
    int size;

    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nla_put_u8(msg, FILE_A_OP_TYPE, status);
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

int enable_file_protect() { return update_file_protect_status(FILE_PROTECT_ENABLE); }

int disable_file_protect() { return update_file_protect_status(FILE_PROTECT_DISABLE); }

int set_file_protect(const std::string &path, file_perm_t perm) {
    int error = 0;
    struct nl_msg *msg;
    int size;

    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nla_put_u8(msg, FILE_A_OP_TYPE, FILE_PROTECT_SET);
    if (error) {
        LOG("nla_put_u8 failed");
        goto errout;
    }

    error = nla_put_string(msg, FILE_A_NAME, path.data());
    if (error) {
        LOG("nla_put_string failed");
        goto errout;
    }
    error = nla_put_s32(msg, FILE_A_PERM, perm);
    if (error) {
        LOG("nla_put_u32 failed");
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
