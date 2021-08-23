#ifndef HACKERNEL_PROCESS_H
#define HACKERNEL_PROCESS_H

#include "syscall.h"
#include <net/genetlink.h>
#include <net/netlink.h>

enum {
	PROCESS_A_UNSPEC,
	PROCESS_A_STATUS_CODE,
	PROCESS_A_OP_TYPE,
	PROCESS_A_NAME,
	PROCESS_A_PERM,
	PROCESS_A_ID,
	__PROCESS_A_MAX,
};
#define PROCESS_A_MAX (__PROCESS_A_MAX - 1)

#define PROCESS_INVAILD -1
#define PROCESS_WATT 0
#define PROCESS_ACCEPT 1
#define PROCESS_REJECT 2

typedef s32 process_perm_t;
typedef int process_perm_id_t;

struct process_perm_node {
	struct hlist_node node;
	process_perm_id_t id;
	process_perm_t perm;
};

typedef struct process_perm_node process_perm_node_t;

struct process_perm_head {
	struct hlist_head head;
	rwlock_t lock;
};

typedef struct process_perm_head process_perm_head_t;

int process_perm_update(const process_perm_id_t id, const process_perm_t perm);

int enable_process_protect(void);
int disable_process_protect(void);


enum {
	PROCESS_PROTECT_UNSPEC,
	PROCESS_PROTECT_REPORT,
	PROCESS_PROTECT_ENABLE,
	PROCESS_PROTECT_DISABLE
};
int process_protect_handler(struct sk_buff *skb, struct genl_info *info);
int process_protect_report_to_userspace(process_perm_id_t id, char *arg);


#endif
