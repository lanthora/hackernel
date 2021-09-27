#include "command.h"
#include "util.h"

int updateProcessProtectStatus(uint8_t status) {
  struct nl_msg *message = NULL;

  message = nlmsg_alloc();
  genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, g_fam_id, 0, NLM_F_REQUEST,
              HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(message, PROCESS_A_OP_TYPE, status);
  nl_send_auto(g_nl_sock, message);
  nlmsg_free(message);
  return 0;
}

int EnableProcessProtect() {
  return updateProcessProtectStatus(PROCESS_PROTECT_ENABLE);
}
int DisableProcessProtect() {
  return updateProcessProtectStatus(PROCESS_PROTECT_DISABLE);
}

ProcessPerm CheckProcessPerm(char *cmd) {
  ProcessPerm perm = PROCESS_ACCEPT;
  return perm;
}

int ReplyProcessPerm(ProcessPermId id, ProcessPerm perm) {
  struct nl_msg *message = NULL;

  message = nlmsg_alloc();
  genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, g_fam_id, 0, NLM_F_REQUEST,
              HACKERNEL_C_PROCESS_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(message, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
  nla_put_s32(message, PROCESS_A_ID, id);
  nla_put_s32(message, PROCESS_A_PERM, perm);
  nl_send_auto(g_nl_sock, message);
  nlmsg_free(message);
  return 0;
}
