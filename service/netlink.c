#include "netlink.h"
#include "handler.h"
#include "syscall.h"
#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>
#include <stdio.h>

/* 指定头文件属性的类型 */
struct nla_policy hackernel_genl_policy[HACKERNEL_A_MAX + 1] = {
    [HACKERNEL_A_CODE] = {.type = NLA_S32},
    [HACKERNEL_A_SCTH] = {.type = NLA_U64},
    [HACKERNEL_A_NAME] = {.type = NLA_STRING},
    [HACKERNEL_A_PERM] = {.type = NLA_U32},
};

/* 定义命令对应的回调函数 */
struct genl_cmd hackernel_genl_cmds[] = {
    {
        .c_id = HACKERNEL_C_HANDSHAKE,
        .c_name = "HACKERNEL_C_HANDSHAKE",
        .c_maxattr = HACKERNEL_A_MAX,
        .c_attr_policy = hackernel_genl_policy,
        .c_msg_parser = &handshake_handler,
    },
    {
        .c_id = HACKERNEL_C_FILE_PROTECT,
        .c_name = "HACKERNEL_C_FILE_PROTECT",
        .c_maxattr = HACKERNEL_A_MAX,
        .c_attr_policy = hackernel_genl_policy,
        .c_msg_parser = &handshake_handler,
    },
};

struct genl_ops hackernel_genl_ops = {
    .o_name = HACKERNEL_FAMLY_NAME,
    .o_cmds = hackernel_genl_cmds,
    .o_ncmds = ARRAY_SIZE(hackernel_genl_cmds),
};

