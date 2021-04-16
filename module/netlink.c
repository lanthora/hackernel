#include "netlink.h"
#include "syscall.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

static struct genl_family genl_family;

static struct nla_policy nla_policy[HACKERNEL_A_MAX + 1] = {
	[HACKERNEL_A_MSG] = { .type = NLA_STRING },
	[HACKERNEL_A_SYS_CALL_TABLE] = { .type = NLA_U64 },
};

static int handshake_handler(struct sk_buff *skb, struct genl_info *info)
{
	char *msg;
	struct sk_buff *reply;
	void *reply_head;
	char reply_msg[64] = { 0 };
	int error = -ENOMEM;
	unsigned long long sys_call_table;

	// 	检查权限
	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		error = -EPERM;
		goto out;
	}

	// 检查参数
	if (!info->attrs[HACKERNEL_A_MSG]) {
		error = -EINVAL;
		goto out;
	}
	if (!info->attrs[HACKERNEL_A_SYS_CALL_TABLE]) {
		error = -EINVAL;
		goto out;
	}

	// 处理 HACKERNEL_A_MSG 属性
	msg = (char *)nla_data(info->attrs[HACKERNEL_A_MSG]);
	printk(KERN_DEBUG "hackernel: recv: %s\n", msg);

	// 使用用户态传递的 HACKERNEL_A_SYS_CALL_TABLE 初始化系统调用表

	sys_call_table =
		*(u64 *)nla_data(info->attrs[HACKERNEL_A_SYS_CALL_TABLE]);
	error = init_sys_call_table(sys_call_table);
	if (error) {
		printk(KERN_ERR "hackernel: init_sys_call_table failed\n");
		strcpy(reply_msg, "init_sys_call_table failed");
	} else {
		printk(KERN_DEBUG "hackernel: init_sys_call_table: %llx\n",
		       sys_call_table);
		strcpy(reply_msg, "init_sys_call_table success");
	}

	// 在这里直接替换系统调用，这是在做测试，真实使用场景需要根据发送过来的命令进行处理
	if (!error) {
		replace_sys_call();
	}

	// 回传握手结果
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
	error = nla_put_string(reply, HACKERNEL_A_MSG, reply_msg);
	if (error) {
		nlmsg_free(reply);
		goto out;
	}
	printk(KERN_DEBUG "hackernel: send: %s\n", reply_msg);
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
