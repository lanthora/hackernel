#include "netlink.h"
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
static struct nla_policy hackernel_genl_policy[HACKERNEL_A_MAX + 1] = {
    [HACKERNEL_A_MSG] = {.type = NLA_STRING},
    [HACKERNEL_A_SYS_CALL_TABLE] = {.type = NLA_U64},
};

/* 配合libnl-genl库实现的回调函数 */
static int parse_cb(struct nl_msg *msg, void *arg) {
  return genl_handle_msg(msg, NULL);
}

/* 定义具体的回调函数 */
static int handshake_handler(struct nl_cache_ops *unused,
                             struct genl_cmd *genl_cmd,
                             struct genl_info *genl_info, void *arg) {
  char *msg = (char *)nla_data(genl_info->attrs[HACKERNEL_A_MSG]);
  printf("recv: %s\n", msg);
  return 0;
}

/* 定义命令对应的回调函数 */
static struct genl_cmd genl_cmds[] = {
    {
        .c_id = HACKERNEL_C_HANDSHAKE,
        .c_name = "HACKERNEL_C_HANDSHAKE",
        .c_maxattr = HACKERNEL_A_MAX,
        .c_attr_policy = hackernel_genl_policy,
        .c_msg_parser = &handshake_handler,
    },
};

/* 定义famly */
static struct genl_ops ops = {
    .o_name = HACKERNEL_FAMLY_NAME,
    .o_cmds = genl_cmds,
    .o_ncmds = ARRAY_SIZE(genl_cmds),
};

int main() {
  /* 变量初始化 */
  int error = 0;

  /* 与内核通信的socket */
  struct nl_sock *nlsock = nl_socket_alloc();
  genl_connect(nlsock);

  /* 注册回调函数 */
  genl_ops_resolve(nlsock, &ops);
  genl_register_family(&ops);
  int famid = ops.o_id;
  nl_socket_modify_cb(nlsock, NL_CB_VALID, NL_CB_CUSTOM, parse_cb, NULL);

  /* 向内核发送一条消息 */
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST,
              HACKERNEL_C_HANDSHAKE, HACKERNEL_FAMLY_VERSION);
  nla_put_string(msg, HACKERNEL_A_MSG, "hello");

  unsigned long sys_call_table;
  if (init_sys_call_table_addr(&sys_call_table)) {
    printf("init_sys_call_table_addr failed. exit now!\n");
    exit(1);
  }
  nla_put_u64(msg, HACKERNEL_A_SYS_CALL_TABLE, sys_call_table);
  printf("send: sys_call_table: %p\n", sys_call_table);
  nl_send_auto(nlsock, msg);
  nlmsg_free(msg);

  /* 接收内核回传的消息 */
  nl_recvmsgs_default(nlsock);

  /* 释放资源 */
  nl_close(nlsock);
  nl_socket_free(nlsock);

  return 0;
}
