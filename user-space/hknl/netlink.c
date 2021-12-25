#include "hknl/netlink.h"
#include "file/define.h"
#include "hackernel/util.h"
#include "heartbeat/define.h"
#include "hknl/wrapper.h"
#include "net/define.h"
#include "process/define.h"
#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>
#include <stdbool.h>
#include <stdio.h>

static struct nl_sock *nl_sock = NULL;
static int fam_id = 0;

int NetlinkGetFamilyID() {
    return fam_id;
}

struct nl_sock *NetlinkGetNlSock() {
    return nl_sock;
}

static struct nla_policy handshake_policy[HANDSHAKE_A_MAX + 1] = {
    [HANDSHAKE_A_STATUS_CODE] = {.type = NLA_S32},
    [HANDSHAKE_A_SYS_SERVICE_TGID] = {.type = NLA_S32},
};

struct nla_policy process_policy[PROCESS_A_MAX + 1] = {
    [PROCESS_A_SESSION] = {.type = NLA_S32}, [PROCESS_A_STATUS_CODE] = {.type = NLA_S32},
    [PROCESS_A_OP_TYPE] = {.type = NLA_U8},  [PROCESS_A_NAME] = {.type = NLA_STRING},
    [PROCESS_A_PERM] = {.type = NLA_S32},    [PROCESS_A_ID] = {.type = NLA_S32},
};

struct nla_policy file_policy[FILE_A_MAX + 1] = {
    [FILE_A_SESSION] = {.type = NLA_S32}, [FILE_A_STATUS_CODE] = {.type = NLA_S32}, [FILE_A_OP_TYPE] = {.type = NLA_U8},
    [FILE_A_NAME] = {.type = NLA_STRING}, [FILE_A_PERM] = {.type = NLA_S32},
};

struct nla_policy net_policy[NET_A_MAX + 1] = {
    [NET_A_SESSION] = {.type = NLA_S32},      [NET_A_STATUS_CODE] = {.type = NLA_S32},
    [NET_A_OP_TYPE] = {.type = NLA_U8},       [NET_A_ID] = {.type = NLA_S32},
    [NET_A_PRIORITY] = {.type = NLA_S8},      [NET_A_ADDR_SRC_BEGIN] = {.type = NLA_U32},
    [NET_A_ADDR_SRC_END] = {.type = NLA_U32}, [NET_A_ADDR_DST_BEGIN] = {.type = NLA_U32},
    [NET_A_ADDR_DST_END] = {.type = NLA_U32}, [NET_A_PORT_SRC_BEGIN] = {.type = NLA_U16},
    [NET_A_PORT_SRC_END] = {.type = NLA_U16}, [NET_A_PORT_DST_BEGIN] = {.type = NLA_U16},
    [NET_A_PORT_DST_END] = {.type = NLA_U16}, [NET_A_PROTOCOL_BEGIN] = {.type = NLA_U8},
    [NET_A_PROTOCOL_END] = {.type = NLA_U8},  [NET_A_RESPONSE] = {.type = NLA_U32},
    [NET_A_FLAGS] = {.type = NLA_S32},
};

// 在这里扩展 HACKERNEL_C_* 对应的 handler
static struct genl_cmd hackernel_genl_cmds[] = {
    {
        .c_id = HACKERNEL_C_HANDSHAKE,
        .c_name = "HACKERNEL_C_HANDSHAKE",
        .c_maxattr = HANDSHAKE_A_MAX,
        .c_attr_policy = handshake_policy,
        .c_msg_parser = &heartbeat_handler,
    },
    {
        .c_id = HACKERNEL_C_PROCESS_PROTECT,
        .c_name = "HACKERNEL_C_PROCESS_PROTECT",
        .c_maxattr = PROCESS_A_MAX,
        .c_attr_policy = process_policy,
        .c_msg_parser = &process_protect_handler,
    },
    {
        .c_id = HACKERNEL_C_FILE_PROTECT,
        .c_name = "HACKERNEL_C_FILE_PROTECT",
        .c_maxattr = FILE_A_MAX,
        .c_attr_policy = file_policy,
        .c_msg_parser = &file_protect_handler,
    },
    {
        .c_id = HACKERNEL_C_NET_PROTECT,
        .c_name = "HACKERNEL_C_NET_PROTECT",
        .c_maxattr = NET_A_MAX,
        .c_attr_policy = net_policy,
        .c_msg_parser = &net_protect_handler,
    },
};

static struct genl_ops hackernel_genl_ops = {
    .o_name = HACKERNEL_FAMLY_NAME,
    .o_cmds = hackernel_genl_cmds,
    .o_ncmds = ARRAY_SIZE(hackernel_genl_cmds),
};

void NetlinkServerInit() {
    int error;

    if (nl_sock) {
        ERR("Generic Netlink has been inited");
        goto errout;
    }

    nl_sock = nl_socket_alloc();
    if (!nl_sock) {
        ERR("Netlink Socket memory alloc failed");
        goto errout;
    }

    error = genl_connect(nl_sock);
    if (error) {
        ERR("Generic Netlink connect failed");
        goto errout;
    }

    // 缓冲区大小设置为4MB
    const int buff_size = 4 * 1024 * 1024;
    error = nl_socket_set_buffer_size(nl_sock, buff_size, buff_size);
    if (error) {
        ERR("nl_socket_set_buffer_size failed");
        goto errout;
    }

    error = genl_ops_resolve(nl_sock, &hackernel_genl_ops);
    if (error) {
        ERR("Resolve a single Generic Netlink family failed");
        goto errout;
    }

    error = genl_register_family(&hackernel_genl_ops);
    if (error) {
        ERR("Generic Netlink Register failed");
        goto errout;
    }
    fam_id = hackernel_genl_ops.o_id;

    error = nl_socket_modify_cb(nl_sock, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, NULL);
    if (error) {
        ERR("Generic Netlink modify callback failed");
        goto errout;
    }

    error = nl_socket_set_nonblocking(nl_sock);
    if (error) {
        ERR("Generic Netlink set noblocking failed");
        goto errout;
    }

    // 应用层收到消息会检查当前期待收到的seq与上次发送的seq是否一致
    nl_socket_disable_seq_check(nl_sock);

    // 内核收到消息会自动回复确认
    nl_socket_disable_auto_ack(nl_sock);
    return;

errout:
    ERR("Generic Netlink init failed");
    if (nl_sock) {
        nl_close(nl_sock);
        nl_socket_free(nl_sock);
        nl_sock = NULL;
    }

    Shutdown();
}

static bool running = false;

int NetlinkWait() {
    int error;

    struct pollfd fds = {
        .fd = nl_socket_get_fd(NetlinkGetNlSock()),
        .events = POLLIN,
    };

    ThreadNameUpdate("netlink");
    LOG("netlink enter");
    running = GlobalRunningGet();
    while (running) {
        const int nfds = 1;
        const int timeout = 100;

        error = poll(&fds, nfds, timeout);
        if (error == 0) {
            continue;
        }

        if (error < 0) {
            ERR("poll failed");
            Shutdown();
            break;
        }

        error = nl_recvmsgs_default(NetlinkGetNlSock());
        if (error) {
            ERR("error=[%d] msg=[%s]", error, nl_geterror(error));
            Shutdown();
            break;
        }
    }
    LOG("netlink exit");
    nl_close(NetlinkGetNlSock());
    nl_socket_free(NetlinkGetNlSock());

    return 0;
}

int NetlinkExit() {
    running = false;
    return 0;
}
