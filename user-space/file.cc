#include "command.h"
#include "util.h"

static int UpdateFileProtectStatus(uint8_t status) {
  struct nl_msg *message;

  message = nlmsg_alloc();
  genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, g_fam_id, 0, NLM_F_REQUEST,
              HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(message, FILE_A_OP_TYPE, status);
  nl_send_auto(g_nl_sock, message);
  nlmsg_free(message);
  return 0;
}

int EnableFileProtect() { return UpdateFileProtectStatus(FILE_PROTECT_ENABLE); }

int DisableFileProtect() {
  return UpdateFileProtectStatus(FILE_PROTECT_DISABLE);
}

int SetFileProtect(const std::string &path, FilePerm perm) {
  struct nl_msg *message;

  message = nlmsg_alloc();
  genlmsg_put(message, NL_AUTO_PID, NL_AUTO_SEQ, g_fam_id, 0, NLM_F_REQUEST,
              HACKERNEL_C_FILE_PROTECT, HACKERNEL_FAMLY_VERSION);
  nla_put_u8(message, FILE_A_OP_TYPE, FILE_PROTECT_SET);
  nla_put_string(message, FILE_A_NAME, path.data());
  nla_put_s32(message, FILE_A_PERM, perm);
  nl_send_auto(g_nl_sock, message);
  nlmsg_free(message);
  return 0;
}
