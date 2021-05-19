#include "netlink.h"
#include "syscall.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

static struct genl_family genl_family;

static struct nla_policy nla_policy[HACKERNEL_A_MAX + 1] = {
	[HACKERNEL_A_CODE] = { .type = NLA_S32 },
	[HACKERNEL_A_MSG] = { .type = NLA_STRING },
	[HACKERNEL_A_SYS_CALL_TABLE] = { .type = NLA_U64 },
};

static int handshake_permissions_check(struct sk_buff *skb,
				       struct genl_info *info)
{
	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		return -EPERM;
	}

	if (!info->attrs[HACKERNEL_A_SYS_CALL_TABLE]) {
		return -EINVAL;
	}
	return 0;
}

static int handshake_result_build(struct sk_buff *skb, struct genl_info *info,
				  struct handshake_data *data,
				  struct sk_buff *reply)
{
	int error = 0;
	void *head = NULL;

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_HANDSHAKE);
	if (!head) {
		nlmsg_free(reply);
		return -ENOMEM;
	}

	error = nla_put_s32(reply, HACKERNEL_A_CODE, data->code);
	if (error) {
		nlmsg_free(reply);
		return -ENOMEM;
	}

	genlmsg_end(reply, head);
	return 0;
}

static int handshake_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	unsigned long long syscall_table = 0;
	struct handshake_data *data = NULL;
	struct sk_buff *reply = NULL;

	// 检查握手包中的参数
	error = handshake_permissions_check(skb, info);
	if (error) {
		goto out;
	}

	// 为 handshake_data 数据结构分配内存
	data = kzalloc(sizeof(struct handshake_data), GFP_KERNEL);
	if (!data) {
		error = -ENOMEM;
		goto out;
	}

	// 从用户空间获取系统调用表地址，并更新系统调用表全局变量
	syscall_table = nla_get_u64(info->attrs[HACKERNEL_A_SYS_CALL_TABLE]);
	error = init_sys_call_table(syscall_table);

	// 准备返回结果
	data->code = error;

	// 为将要返回给用户空间的数据分配内存
	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply) {
		error = -ENOMEM;
		goto out;
	}

	// 根据 handshake_data 的内容填充分配的内存
	error = handshake_result_build(skb, info, data, reply);
	if (error) {
		goto out;
	}

	// 向用户空间发送消息
	error = genlmsg_reply(reply, info);
out:
	// 释放 handshake_data 内存
	kfree(data);
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
