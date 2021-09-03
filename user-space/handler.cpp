#include "handler.h"
#include "command.h"
#include "netlink.h"
#include "util.h"
#include <iostream>

int handshakeHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                     struct genl_info *genl_info, void *arg) {
  int Code = nla_get_s32(genl_info->attrs[HANDSHAKE_A_STATUS_CODE]);
  if (Code) {
    LOG("handshake Response Code=[%d]", Code);
    exit(1);
  }

  return 0;
}

int processProtectHandler(struct nl_cache_ops *unused,
                          struct genl_cmd *genl_cmd,
                          struct genl_info *genl_info, void *arg) {
  u_int8_t Type = nla_get_u8(genl_info->attrs[PROCESS_A_OP_TYPE]);
  int Error;
  int Id;
  char *Name;
  int Code;
  std::string Msg;

  switch (Type) {
  case PROCESS_PROTECT_ENABLE:
    Code = nla_get_s32(genl_info->attrs[PROCESS_A_STATUS_CODE]);
    LOG("process ctl enable Response Code=[%d]", Code);
    break;

  case PROCESS_PROTECT_REPORT:
    Id = nla_get_s32(genl_info->attrs[PROCESS_A_ID]);
    Name = nla_get_string(genl_info->attrs[PROCESS_A_NAME]);
    Msg.assign(Name);

    std::for_each(Msg.begin(), Msg.end(), [](char &c) {
      if (c == 0x1F)
        c = '#';
    });

    LOG("process: Id=[%d] Name=[%s]", Id, Msg.data());
    Error = replyProcessPerm(Id, checkProcessPerm(Name));
    if (Error)
      LOG("replyProcessPerm failed");

    break;

  default:
    LOG("Unknown process protect command Type");
  }
  return 0;
}

int fileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                       struct genl_info *genl_info, void *arg) {
  u_int8_t Type;
  char *Name;
  file_perm_t Perm;
  int Code;

  Type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
  switch (Type) {
  // 这三个命令暂时公用一个响应处理函数
  case FILE_PROTECT_ENABLE:
  case FILE_PROTECT_DISABLE:
  case FILE_PROTECT_SET:
    Code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
    LOG("file ctrl Response Code=[%d]", Code);
    break;

  case FILE_PROTECT_REPORT:
    Name = nla_get_string(genl_info->attrs[FILE_A_NAME]);
    Perm = nla_get_s32(genl_info->attrs[FILE_A_PERM]);
    LOG("file: Name=[%s] Perm=[%d]", Name, Perm);
    break;

  default:
    LOG("Unknown process protect command Type");
  }

  return 0;
}

/**
 * 在这里处理内核返回的命令结果
 */
int netProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                      struct genl_info *genl_info, void *arg) {
  u_int8_t Type;
  int Code;

  Type = nla_get_u8(genl_info->attrs[NET_A_OP_TYPE]);
  switch (Type) {
  case NET_PROTECT_ENABLE:
  case NET_PROTECT_DISABLE:
  case NET_PROTECT_INSERT:
  case NET_PROTECT_DELETE:
    Code = nla_get_s32(genl_info->attrs[NET_A_STATUS_CODE]);
    LOG("net ctrl Response Code=[%d]", Code);
    break;

  default:
    LOG("Unknown net protect command Type");
  }
  return 0;
}
