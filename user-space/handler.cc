#include "handler.h"

#include <iostream>

#include "command.h"
#include "netlink.h"
#include "util.h"

int HandshakeHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                     struct genl_info *genl_info, void *arg) {
  int code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
  if (code) {
    LOG("handshake response code=[%d]", code);
    LOG("handshake failed. exit");
    exit(1);
  }

  return 0;
}

int ProcessProtectHandler(struct nl_cache_ops *unused,
                          struct genl_cmd *genl_cmd,
                          struct genl_info *genl_info, void *arg) {
  u_int8_t type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
  int error, id, code;
  char *name;
  std::string msg;

  switch (type) {
    case PROCESS_PROTECT_ENABLE:
      code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
      LOG("process ctl enable response code=[%d]", code);
      break;

    case PROCESS_PROTECT_REPORT:
      id = nla_get_s32(genl_info->attrs[PROCESS_A_ID]);
      name = nla_get_string(genl_info->attrs[PROCESS_A_NAME]);
      msg.assign(name);

      std::for_each(msg.begin(), msg.end(), [](char &c) {
        if (c == 0x1F) c = '#';
      });

      LOG("process: id=[%d] name=[%s]", id, msg.data());
      error = ReplyProcessPerm(id, CheckProcessPerm(name));
      if (error) LOG("reply_process_perm failed");

      break;

    default:
      LOG("Unknown process protect command Type");
  }
  return 0;
}

int FileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                       struct genl_info *genl_info, void *arg) {
  u_int8_t type;
  char *name;
  FilePerm perm;
  int code;

  type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
  switch (type) {
    // TODO: 根据业务分别处理case,目前只是打印日志
    case FILE_PROTECT_ENABLE:
    case FILE_PROTECT_DISABLE:
    case FILE_PROTECT_SET:
      code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
      LOG("file ctrl response code=[%d]", code);
      break;

    case FILE_PROTECT_REPORT:
      name = nla_get_string(genl_info->attrs[FILE_A_NAME]);
      perm = nla_get_s32(genl_info->attrs[FILE_A_PERM]);
      LOG("file: name=[%s] perm=[%d]", name, perm);
      break;

    default:
      LOG("Unknown process protect command Type");
  }

  return 0;
}

int NetProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                      struct genl_info *genl_info, void *arg) {
  u_int8_t type;
  int code;

  type = nla_get_u8(genl_info->attrs[NET_A_OP_TYPE]);
  switch (type) {
    case NET_PROTECT_ENABLE:
    case NET_PROTECT_DISABLE:
    case NET_PROTECT_INSERT:
    case NET_PROTECT_DELETE:
      code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
      LOG("net ctrl response code=[%d]", code);
      break;

    default:
      LOG("Unknown net protect command Type");
  }
  return 0;
}
