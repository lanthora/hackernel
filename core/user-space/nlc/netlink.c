/* SPDX-License-Identifier: GPL-2.0-only */
#include "nlc/netlink.h"
#include "file/define.h"
#include "hackernel/util.h"
#include "heartbeat/define.h"
#include "net/define.h"
#include "nlc/wrapper.h"
#include "process/define.h"
#include <errno.h>
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

static struct nla_policy handshake_policy[HANDSHAKE_A_MAX + 1] = {
    [HANDSHAKE_A_STATUS_CODE] = {.type = NLA_S32},
    [HANDSHAKE_A_SYS_SERVICE_TGID] = {.type = NLA_S32},
};

struct nla_policy process_policy[PROCESS_A_MAX + 1] = {
    [PROCESS_A_SESSION] = {.type = NLA_S32},   [PROCESS_A_STATUS_CODE] = {.type = NLA_S32},
    [PROCESS_A_OP_TYPE] = {.type = NLA_U8},    [PROCESS_A_WORKDIR] = {.type = NLA_STRING},
    [PROCESS_A_BINARY] = {.type = NLA_STRING}, [PROCESS_A_ARGV] = {.type = NLA_STRING},
    [PROCESS_A_PERM] = {.type = NLA_S32},      [PROCESS_A_ID] = {.type = NLA_S32},
};

struct nla_policy file_policy[FILE_A_MAX + 1] = {
    [FILE_A_SESSION] = {.type = NLA_S32}, [FILE_A_STATUS_CODE] = {.type = NLA_S32}, [FILE_A_OP_TYPE] = {.type = NLA_U8},
    [FILE_A_NAME] = {.type = NLA_STRING}, [FILE_A_PERM] = {.type = NLA_S32},        [FILE_A_FLAG] = {.type = NLA_S32},
    [FILE_A_FSID] = {.type = NLA_U64},    [FILE_A_INO] = {.type = NLA_U64}};

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
        .c_msg_parser = &process_protection_handler,
    },
    {
        .c_id = HACKERNEL_C_FILE_PROTECT,
        .c_name = "HACKERNEL_C_FILE_PROTECT",
        .c_maxattr = FILE_A_MAX,
        .c_attr_policy = file_policy,
        .c_msg_parser = &file_protection_handler,
    },
    {
        .c_id = HACKERNEL_C_NET_PROTECT,
        .c_name = "HACKERNEL_C_NET_PROTECT",
        .c_maxattr = NET_A_MAX,
        .c_attr_policy = net_policy,
        .c_msg_parser = &net_protection_handler,
    },
};

static struct genl_ops hackernel_genl_ops = {
    .o_name = HACKERNEL_FAMLY_NAME,
    .o_cmds = hackernel_genl_cmds,
    .o_ncmds = ARRAY_SIZE(hackernel_genl_cmds),
};

void init_netlink_server() {
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
    static const int buff_size = 4 * 1024 * 1024;
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

    shutdown_service(HACKERNEL_NETLINK_INIT);
}

static bool is_running = false;

int start_netlink() {
    int error;

    if (!nl_sock) {
        ERR("nl_sock is not inited");
        return 0;
    }

    struct pollfd fds = {
        .fd = nl_socket_get_fd(nl_sock),
        .events = POLLIN,
    };

    update_thread_name("netlink");
    DBG("netlink enter");
    is_running = current_service_status();
    while (is_running) {
        static const nfds_t nfds = 1;
        static const int timeout = HEARTBEAT_INTERVAL * 2;
        const int total = poll(&fds, nfds, timeout);

        // 服务正常退出时,如果心跳线程先结束,会导致此处会出现超时,这属于正常逻辑,
        // 不应该产生错误日志.因此检测到进程处于退出状态时跳出循环.
        if (!is_running) {
            break;
        }

        // 返回值等于0时表示超时,在有心跳存在的情况下,
        // 等待时间超过两次心跳表示内核没有向上返回结果,是异常情况
        if (total == 0) {
            ERR("poll timeout");
            shutdown_service(HACKERNEL_NETLINK_WAIT);
            break;
        }
        if (total == -1) {
            ERR("poll failed, errno=[%d] errmsg=[%s]", errno, strerror(errno));
            shutdown_service(HACKERNEL_NETLINK_WAIT);
            break;
        }
        error = nl_recvmsgs_default(nl_sock);
        if (error) {
            ERR("error=[%d] msg=[%s]", error, nl_geterror(error));
            shutdown_service(HACKERNEL_NETLINK_WAIT);
            break;
        }
    }
    DBG("netlink exit");
    if (nl_sock) {
        nl_close(nl_sock);
        nl_socket_free(nl_sock);
        nl_sock = NULL;
    }

    return 0;
}

int stop_netlink() {
    is_running = false;
    return 0;
}

struct nl_msg *alloc_hackernel_nlmsg(uint8_t cmd) {
    struct nl_msg *message;

    message = nlmsg_alloc();
    if (!message) {
        ERR("nlmsg_alloc failed");
        return NULL;
    }
    genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, fam_id, 0, NLM_F_REQUEST, cmd, HACKERNEL_FAMLY_VERSION);
    return message;
}

int send_free_hackernel_nlmsg(struct nl_msg *message) {
    int error = 0;

    if (!nl_sock)
        return -EFAULT;

    error = nl_send_auto(nl_sock, message);
    nlmsg_free(message);
    return error;
}
