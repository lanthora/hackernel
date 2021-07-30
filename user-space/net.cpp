#include "command.h"
#include "util.h"

/**
 * 在这里面构造netlink协议包,发送到内核
 */

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
    error = nla_put_u8(msg, NET_A_OP_TYPE, status);
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

int net_policy_insert(const net_policy_t &policy) { return 0; }
int net_policy_delete(policy_id_t id) { return 0; }

int enable_net_protect() { return update_net_protect_status(NET_PROTECT_ENABLE); }
int disable_net_protect() { return update_net_protect_status(NET_PROTECT_DISABLE); }
