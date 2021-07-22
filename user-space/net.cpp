#include "command.h"
#include "util.h"

static int update_net_protect_status(uint8_t status) {
    int error = 0;
    struct nl_msg *msg;
    int size;

    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_NET_PROTECT, HACKERNEL_FAMLY_VERSION);
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

int enable_net_protect() { return update_net_protect_status(NET_PROTECT_ENABLE); }
int disable_net_protect() { return update_net_protect_status(NET_PROTECT_DISABLE); }

int set_net_protect(net_port_t port, net_perm_t perm) { return set_net_protect(port, 1, perm); }

int set_net_protect(net_port_t port, net_port_range_t range, net_perm_t perm) {
    int error = 0;
    struct nl_msg *msg;
    int size;

    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        goto errout;
    }
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_NET_PROTECT, HACKERNEL_FAMLY_VERSION);
    error = nla_put_u8(msg, HACKERNEL_A_OP_TYPE, NET_PROTECT_SET);
    if (error) {
        LOG("nla_put_u8 failed");
        goto errout;
    }

    error = nla_put_u16(msg, HACKERNEL_A_PORT, port);
    if (error) {
        LOG("nla_put_string failed");
        goto errout;
    }

    error = nla_put_u16(msg, HACKERNEL_A_PORT_RANGE, range);
    if (error) {
        LOG("nla_put_string failed");
        goto errout;
    }

    error = nla_put_s32(msg, HACKERNEL_A_PERM, perm);
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