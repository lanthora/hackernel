#ifndef HACKERNEL_PROCESS_H
#define HACKERNEL_PROCESS_H

#include "syscall.h"
#include <net/genetlink.h>
#include <net/netlink.h>

DEFINE_HOOK_HEADER(execve);
DEFINE_HOOK_HEADER(execveat);

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

typedef s32 process_perm_t;
typedef int process_perm_id_t;

int process_perm_init(void);
int process_perm_destory(void);

enum {
	PROCESS_PROTECT_UNSPEC,
	PROCESS_PROTECT_REPORT,
	PROCESS_PROTECT_ENABLE,
	PROCESS_PROTECT_DISABLE
};

extern int process_protect_handler(struct sk_buff *skb, struct genl_info *info);

// 开关进程保护
int enable_process_protect(void);
int disable_process_protect(void);


#endif