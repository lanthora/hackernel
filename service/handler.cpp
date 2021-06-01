#include "handler.h"
#include "netlink.h"
#include <iostream>

int handshake_handler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd,
                      struct genl_info *genl_info, void *arg) {
  int code = nla_get_s32(genl_info->attrs[HACKERNEL_A_CODE]);
  std::cout << "recv: code=" << code << std::endl;
  return code;
}
