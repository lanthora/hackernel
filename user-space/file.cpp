#include "command.h"
#include "util.h"

static int updateFileProtectStatus(uint8_t Status) {

  struct nl_msg *Message;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, FILE_A_OP_TYPE, Status);
  nl_send_auto(NlSock, Message);
  nlmsg_free(Message);
  return 0;
}

int enableFileProtect() {
  return updateFileProtectStatus(FILE_PROTECT_ENABLE);
}

int disableFileProtect() {
  return updateFileProtectStatus(FILE_PROTECT_DISABLE);
}

int setFileProtect(const std::string &Path, file_perm_t Perm) {

  struct nl_msg *Message;

  Message = nlmsg_alloc();
  genlmsg_put(Message, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(Message, FILE_A_OP_TYPE, FILE_PROTECT_SET);
  nla_put_string(Message, FILE_A_NAME, Path.data());
  nla_put_s32(Message, FILE_A_PERM, Perm);
  nl_send_auto(NlSock, Message);
  nlmsg_free(Message);
  return 0;
}
