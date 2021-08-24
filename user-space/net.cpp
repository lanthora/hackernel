#include "command.h"
#include "util.h"

/**
 * 在这里面构造netlink协议包,发送到内核
 */

static int update_net_protect_status(uint8_t Status) {

  struct nl_msg *Message;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_NET_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, NET_A_OP_TYPE, Status);
  nl_send_auto(NlSock, Message);

  return 0;
}

int netPolicyInsert(const NetPolicy &Policy) {
  struct nl_msg *Message;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_NET_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, NET_A_OP_TYPE, NET_PROTECT_INSERT);

  nla_put_s32(Message, NET_A_ID, Policy.Id);
  nla_put_s8(Message, NET_A_PRIORITY, Policy.Priority);

  nla_put_u32(Message, NET_A_ADDR_SRC_BEGIN, Policy.Addr.Src.Begin);
  nla_put_u32(Message, NET_A_ADDR_SRC_END, Policy.Addr.Src.End);
  nla_put_u32(Message, NET_A_ADDR_DST_BEGIN, Policy.Addr.Dst.Begin);
  nla_put_u32(Message, NET_A_ADDR_DST_END, Policy.Addr.Dst.End);

  nla_put_u16(Message, NET_A_PORT_SRC_BEGIN, Policy.Port.Src.Begin);
  nla_put_u16(Message, NET_A_PORT_SRC_END, Policy.Port.Src.End);
  nla_put_u16(Message, NET_A_PORT_DST_BEGIN, Policy.Port.Dst.Begin);
  nla_put_u16(Message, NET_A_PORT_DST_END, Policy.Port.Dst.End);

  nla_put_u8(Message, NET_A_PROTOCOL_BEGIN, Policy.Protocol.Begin);
  nla_put_u8(Message, NET_A_PROTOCOL_END, Policy.Protocol.End);

  nla_put_u32(Message, NET_A_RESPONSE, Policy.Response);
  nla_put_s32(Message, NET_A_FLAGS, Policy.Flags);

  nl_send_auto(NlSock, Message);

  return 0;
}
int netPolicyDelete(NetPolicyId Id) {
  struct nl_msg *Message;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_NET_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, NET_A_OP_TYPE, NET_PROTECT_DELETE);
  nla_put_u32(Message, NET_A_ID, Id);
  nl_send_auto(NlSock, Message);

  return 0;
}

int enableNetProtect() {
  return update_net_protect_status(NET_PROTECT_ENABLE);
}
int disableNetProtect() {
  return update_net_protect_status(NET_PROTECT_DISABLE);
}
