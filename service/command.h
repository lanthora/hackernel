#ifndef HACKERNEL_COMMAND_H
#define HACKERNEL_COMMAND_H
#include "netlink.h"
#include <cstdint>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <string>

// handshake
int handshake();
// handshake end

// file protect
typedef int32_t file_perm_t;

#define READ_PROTECT_MASK 1
#define WRITE_PROTECT_MASK 2
#define UNLINK_PROTECT_MASK 4
#define RENAME_PROTECT_MASK 8

#define FILE_PROTECT_ENABLE 1
#define FILE_PROTECT_DISABLE 2
#define FILE_PROTECT_SET 3
#define FILE_PROTECT_NOTIFY 4

int enable_file_protect();
int set_file_protect(const std::string &path, file_perm_t perm);
// file protect end

// process protect
typedef int process_perm_id_t;
typedef int32_t process_perm_t;
#define PROCESS_PROTECT_ENABLE 1
#define PROCESS_PROTECT_REPORT 2

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

int enable_process_protect();
process_perm_t check_precess_perm(char *cmd);
int reply_process_perm(process_perm_id_t id, process_perm_t perm);
// process protect end

#endif