#include "netlink.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

static struct genl_family genl_family;

static struct nla_policy nla_policy[HACKERNEL_A_MAX + 1] = {
	[HACKERNEL_A_MSG] = { .type = NLA_STRING },
};

static int handshake_handler(struct sk_buff *skb, struct genl_info *info)
{
	char *msg;
	struct sk_buff *reply;
	void *reply_head;
	int error = -ENOMEM;

	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		error = -EPERM;
		goto out;
	}
	if (!info->attrs[HACKERNEL_A_MSG]) {
		error = -EINVAL;
		goto out;
	}
	msg = (char *)nla_data(info->attrs[HACKERNEL_A_MSG]);
	printk(KERN_INFO "hackernel: recv: %s\n", msg);

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply) {
		goto out;
	}

	reply_head = genlmsg_put_reply(reply, info, &genl_family, 0,
				       HACKERNEL_C_HANDSHAKE);
	if (!reply_head) {
		nlmsg_free(reply);
		goto out;
	}

	error = nla_put_string(reply, HACKERNEL_A_MSG, "world");
	if (error) {
		nlmsg_free(reply);
		goto out;
	}
	printk(KERN_INFO "hackernel: send: world\n");

	genlmsg_end(reply, reply_head);
	error = genlmsg_reply(reply, info);

out:
	return error;
}

static struct genl_small_ops genl_small_ops[] = {
	{
		.cmd = HACKERNEL_C_HANDSHAKE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = handshake_handler,
	},
};

static struct genl_family genl_family = {
	.hdrsize = 0,
	.name = HACKERNEL_FAMLY_NAME,
	.version = HACKERNEL_FAMLY_VERSION,
	.module = THIS_MODULE,
	.small_ops = genl_small_ops,
	.n_small_ops = ARRAY_SIZE(genl_small_ops),
	.maxattr = HACKERNEL_A_MAX,
	.policy = nla_policy,
};

void netlink_kernel_start(void)
{
	int error = 0;

	error = genl_register_family(&genl_family);
	if (error) {
		printk(KERN_ERR "hackernel: genl_register_family failed\n");
	}
}

void netlink_kernel_stop(void)
{
	int error = 0;

	error = genl_unregister_family(&genl_family);
	if (error) {
		printk(KERN_ERR "hackernel: genl_unregister_family failed\n");
	}
}
