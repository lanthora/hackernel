#include "handler.h"
#include "netlink.h"
#include "syscall.h"
#include <iostream>
#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/msg.h>

int main() {
  int error = 0;
  struct nl_msg *msg;
  struct nl_sock *nlsock;

  nlsock = nl_socket_alloc();
  genl_connect(nlsock);

  genl_ops_resolve(nlsock, &hackernel_genl_ops);
  genl_register_family(&hackernel_genl_ops);
  int famid = hackernel_genl_ops.o_id;
  nl_socket_modify_cb(nlsock, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, NULL);

  {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST,
                HACKERNEL_C_HANDSHAKE, HACKERNEL_FAMLY_VERSION);

    unsigned long sys_call_table;
    if (init_sys_call_table_addr(&sys_call_table)) {
      nlmsg_free(msg);
      exit(1);
    }
    nla_put_u64(msg, HACKERNEL_A_SCTH, sys_call_table);

    nl_send_sync(nlsock, msg);

    nl_recvmsgs_default(nlsock);
  }

  {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST,
                HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
    nl_send_sync(nlsock, msg);

    // 目前还没有实现开启进程保护的返回结果,recv阻塞后不会返回
    // error = nl_recvmsgs_default(nlsock);
    // printf("error = %d \n", error);
  }

  {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST,
                HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    nla_put_u32(msg, HACKERNEL_A_CODE, FILE_PROTECT_ENABLE);
    nl_send_sync(nlsock, msg);

    nl_recvmsgs_default(nlsock);
  }

  {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST,
                HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    nla_put_s32(msg, HACKERNEL_A_CODE, FILE_PROTECT_SET);
    nla_put_string(msg, HACKERNEL_A_NAME, "/root/test/protect/modify-me");
    nla_put_u32(msg, HACKERNEL_A_PERM, 14);
    nl_send_sync(nlsock, msg);

    nl_recvmsgs_default(nlsock);
  }
  {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST,
                HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
    nla_put_s32(msg, HACKERNEL_A_CODE, FILE_PROTECT_SET);
    nla_put_string(msg, HACKERNEL_A_NAME, "/root/test/protect");
    nla_put_u32(msg, HACKERNEL_A_PERM, 10);
    nl_send_sync(nlsock, msg);

    nl_recvmsgs_default(nlsock);
  }

  nl_close(nlsock);
  nl_socket_free(nlsock);

  return 0;
}
