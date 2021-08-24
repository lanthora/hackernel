#include "command.h"
#include "util.h"

static int updateFileProtectStatus(uint8_t Status) {

  struct nl_msg *msg;

  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(msg, FILE_A_OP_TYPE, Status);
  nl_send_auto(NlSock, msg);
  nlmsg_free(msg);
  return 0;
}

int enableFileProtect() {
  return updateFileProtectStatus(FILE_PROTECT_ENABLE);
}

int disableFileProtect() {
  return updateFileProtectStatus(FILE_PROTECT_DISABLE);
}

int setFileProtect(const std::string &path, file_perm_t perm) {

  struct nl_msg *msg;

  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(msg, FILE_A_OP_TYPE, FILE_PROTECT_SET);
  nla_put_string(msg, FILE_A_NAME, path.data());
  nla_put_s32(msg, FILE_A_PERM, perm);
  nl_send_auto(NlSock, msg);
  nlmsg_free(msg);
  return 0;
}
