#include <linux/kernel.h>
#include <net/genetlink.h>
#include <net/netlink.h>

typedef u16 net_port_t;
typedef s32 net_perm_t;

enum {
	NET_PROTECT_UNSPEC,
	NET_PROTECT_REPORT,
	NET_PROTECT_ENABLE,
	NET_PROTECT_DISABLE,
	NET_PROTECT_SET
};

int net_protect_handler(struct sk_buff *skb, struct genl_info *info);
void exit_net_protect(void);