#ifndef HACKERNEL_COMMAND_H
#define HACKERNEL_COMMAND_H
#include "netlink.h"
#include <cstdint>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <string>

typedef u_int32_t perm_t;

#define READ_PROTECT_MASK 1
#define WRITE_PROTECT_MASK 2
#define UNLINK_PROTECT_MASK 4
#define RENAME_PROTECT_MASK 8

#define FILE_PROTECT_ENABLE 1
#define FILE_PROTECT_DISABLE 2
#define FILE_PROTECT_SET 3
#define FILE_PROTECT_NOTIFY 4

#define PROCESS_PROTECT_ENABLE 1
#define PROCESS_PROTECT_NOTIFY 2

int handshake();
int enable_process_protect();
int enable_file_protect();
int set_file_protect(const std::string &path, perm_t perm);

#endif