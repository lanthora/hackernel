#include "net.h"

static int enable_net_protect(void)
{
	return 0;
}

static int disable_net_protect(void)
{
	return 0;
}

void exit_net_protect(void)
{
	disable_net_protect();
}

int net_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}