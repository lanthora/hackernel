#include "netlink.h"
#include "fperm.h"
#include "syscall.h"
#include "util.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

static struct genl_family genl_family;

static struct nla_policy nla_policy[HACKERNEL_A_MAX + 1] = {
	[HACKERNEL_A_CODE] = { .type = NLA_S32 },
	[HACKERNEL_A_SCTH] = { .type = NLA_U64 },
	[HACKERNEL_A_NAME] = { .type = NLA_STRING },
	[HACKERNEL_A_PERM] = { .type = NLA_U32 },
};

static int handshake_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	unsigned long long syscall_table = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	int code;
	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		code = -EPERM;
		LOG("netlink_capable failed");
		goto response;
	}

	if (!info->attrs[HACKERNEL_A_SCTH]) {
		code = -EINVAL;
		LOG("HACKERNEL_A_SCTH failed");
		goto response;
	}

	syscall_table = nla_get_u64(info->attrs[HACKERNEL_A_SCTH]);
	code = init_sys_call_table(syscall_table);

response:

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto err;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_HANDSHAKE);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto err;
	}

	error = nla_put_s32(reply, HACKERNEL_A_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto err;
	}

	genlmsg_end(reply, head);

	// reply指向的内存由 genlmsg_reply 释放
	// 此处调用 nlmsg_free(reply) 会引起内核crash
	error = genlmsg_reply(reply, info);
	if (unlikely(error)) {
		LOG("genlmsg_reply failed");
	}
	return 0;
err:
	nlmsg_free(reply);
	return 0;
}

static int process_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	enable_process_protect();
	return 0;
}

static int file_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	int code = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		code = -EPERM;
		goto response;
	}

	if (!info->attrs[HACKERNEL_A_CODE]) {
		code = -EINVAL;
		goto response;
	}

	code = nla_get_s32(info->attrs[HACKERNEL_A_CODE]);
	switch (code) {
	case FILE_PROTECT_ENABLE: {
		code = enable_file_protect();
		break;
	}
	case FILE_PROTECT_DISABLE: {
		code = disable_file_protect();
		break;
	}

	case FILE_PROTECT_SET: {
		perm_t perm;
		char *path;
		path = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!path) {
			code = -ENOMEM;
			goto response;
		}

		if (!info->attrs[HACKERNEL_A_NAME]) {
			code = -EINVAL;
			kfree(path);
			goto response;
		}

		if (!info->attrs[HACKERNEL_A_PERM]) {
			code = -EINVAL;
			kfree(path);
			goto response;
		}
		nla_strscpy(path, info->attrs[HACKERNEL_A_NAME], PATH_MAX);
		perm = nla_get_s32(info->attrs[HACKERNEL_A_PERM]);
		code = fperm_set_path(path, perm);
		kfree(path);
		break;
	}

	default: {
		LOG("Unknown file protect command");
	}
	}

response:

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto err;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_FILE_PROTECT);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto err;
	}

	error = nla_put_s32(reply, HACKERNEL_A_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto err;
	}

	genlmsg_end(reply, head);

	// reply指向的内存由 genlmsg_reply 释放
	// 此处调用 nlmsg_free(reply) 会引起内核crash
	error = genlmsg_reply(reply, info);
	if (unlikely(error)) {
		LOG("genlmsg_reply failed");
	}
	return 0;
err:
	nlmsg_free(reply);
	return 0;
}

static struct genl_small_ops genl_small_ops[] = {
	{
		.cmd = HACKERNEL_C_HANDSHAKE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = handshake_handler,
	},
	{
		.cmd = HACKERNEL_C_PROCESS_PROTECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = process_protect_handler,
	},
	{
		.cmd = HACKERNEL_C_FILE_PROTECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = file_protect_handler,
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
		LOG("genl_register_family failed");
	}
}

void netlink_kernel_stop(void)
{
	int error = 0;

	error = genl_unregister_family(&genl_family);
	if (error) {
		LOG("genl_unregister_family failed");
	}
}
