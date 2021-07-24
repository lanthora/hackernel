#ifndef HACKERNEL_COMLAYER_H
#define HACKERNEL_COMLAYER_H

#include "file.h"
#include "netlink.h"
#include "process.h"
#include <linux/genetlink.h>
#include <linux/kernel.h>

int handshake_handler(struct sk_buff *skb, struct genl_info *info);

enum {
	FILE_PROTECT_UNSPEC,
	FILE_PROTECT_REPORT,
	FILE_PROTECT_ENABLE,
	FILE_PROTECT_DISABLE,
	FILE_PROTECT_SET
};
int file_protect_handler(struct sk_buff *skb, struct genl_info *info);
int file_protect_report_to_userspace(struct file_perm_data *data);

enum {
	PROCESS_PROTECT_UNSPEC,
	PROCESS_PROTECT_REPORT,
	PROCESS_PROTECT_ENABLE,
	PROCESS_PROTECT_DISABLE
};
int process_protect_handler(struct sk_buff *skb, struct genl_info *info);
int process_protect_report_to_userspace(process_perm_id_t id, char *arg);

enum {
	NET_PROTECT_UNSPEC,
	NET_PROTECT_REPORT,
	NET_PROTECT_ENABLE,
	NET_PROTECT_DISABLE,
	NET_PROTECT_SET
};
int net_protect_handler(struct sk_buff *skb, struct genl_info *info);

#endif
