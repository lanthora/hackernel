#include "command.h"
#include "util.h"

int updateProcessProtectStatus(uint8_t Status) {

  struct nl_msg *Message = NULL;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, PROCESS_A_OP_TYPE, Status);
  nl_send_auto(NlSock, Message);
  nlmsg_free(Message);
  return 0;
}

int enableProcessProtect() {
  return updateProcessProtectStatus(PROCESS_PROTECT_ENABLE);
}
int disableProcessProtect() {
  return updateProcessProtectStatus(PROCESS_PROTECT_DISABLE);
}

ProcessPerm checkProcessPerm(char *Cmd) {
  ProcessPerm Perm = PROCESS_ACCEPT;
  return Perm;
}

int replyProcessPerm(ProcessPermId Id, ProcessPerm Perm) {

  struct nl_msg *Message = NULL;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
  nla_put_s32(Message, PROCESS_A_ID, Id);
  nla_put_s32(Message, PROCESS_A_PERM, Perm);
  nl_send_auto(NlSock, Message);
  nlmsg_free(Message);
  return 0;
}
