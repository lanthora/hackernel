#ifndef HACKERNEL_COMLAYER_H
#define HACKERNEL_COMLAYER_H

#include "file.h"
#include "netlink.h"
#include "process.h"
#include <linux/genetlink.h>
#include <linux/kernel.h>

int file_protect_handler(struct sk_buff *skb, struct genl_info *info);
int file_protect_report_to_userspace(struct file_perm_data *data);

int process_protect_handler(struct sk_buff *skb, struct genl_info *info);
int process_protect_report_to_userspace(process_perm_id_t id, char *arg);
#endif
