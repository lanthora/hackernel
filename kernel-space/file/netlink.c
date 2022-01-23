/* SPDX-License-Identifier: GPL-2.0-only */
#include "netlink.h"
#include "file.h"
#include "handshake.h"
#include "watchdog.h"
#include <linux/version.h>

#if CONFIG_NLA_STRSCPY
#define nla_strscpy nla_strlcpy
#endif

struct nla_policy file_policy[FILE_A_MAX + 1] = {
	[FILE_A_STATUS_CODE] = { .type = NLA_S32 },
	[FILE_A_SESSION] = { .type = NLA_S32 },

	[FILE_A_OP_TYPE] = { .type = NLA_U8 },
	[FILE_A_NAME] = { .type = NLA_STRING },
	[FILE_A_PERM] = { .type = NLA_S32 },
};

extern struct genl_family genl_family;

int file_protect_report_to_userspace(struct file_perm_data *data)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;
	const char *filename = data->path;
	const file_perm_t perm = data->marked_perm;
	int errcnt;
	static atomic_t atomic_errcnt = ATOMIC_INIT(0);

	if (!filename)
		ERR("filename is null");

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if ((!skb)) {
		ERR("genlmsg_new failed");
		error = -ENOMEM;
		goto errout;
	}

	head = genlmsg_put(skb, g_portid, 0, &genl_family, 0,
			   HACKERNEL_C_FILE_PROTECT);
	if (!head) {
		ERR("genlmsg_put failed");
		error = -ENOMEM;
		goto errout;
	}
	error = nla_put_u8(skb, FILE_A_OP_TYPE, FILE_PROTECT_REPORT);
	if (error) {
		ERR("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, FILE_A_PERM, perm);
	if (error) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, FILE_A_NAME, filename);
	if (error) {
		ERR("nla_put_string failed");
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, g_portid);
	if (!error) {
		errcnt = atomic_xchg(&atomic_errcnt, 0);
		if (unlikely(errcnt))
			ERR("errcnt=[%u]", errcnt);

		goto out;
	}

	atomic_inc(&atomic_errcnt);

	if (error == -EAGAIN) {
		goto out;
	}

	conn_check_set_dead();

	ERR("genlmsg_unicast failed error=[%d]", error);

out:
	return 0;
errout:
	nlmsg_free(skb);
	return error;
}

int file_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	int code = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	u8 type;
	s32 session;

	if (g_portid != info->snd_portid)
		return -EPERM;

	if (!info->attrs[FILE_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[FILE_A_OP_TYPE]);
	switch (type) {
	case FILE_PROTECT_ENABLE: {
		code = file_protect_enable();
		goto response;
	}
	case FILE_PROTECT_DISABLE: {
		code = file_protect_disable();
		goto response;
	}
	case FILE_PROTECT_SET: {
		file_perm_t perm;
		char *path;

		if (!info->attrs[FILE_A_NAME]) {
			code = -EINVAL;
			goto response;
		}

		if (!info->attrs[FILE_A_PERM]) {
			code = -EINVAL;
			goto response;
		}

		path = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!path) {
			code = -ENOMEM;
			goto response;
		}

		nla_strscpy(path, info->attrs[FILE_A_NAME], PATH_MAX);
		perm = nla_get_s32(info->attrs[FILE_A_PERM]);
		code = file_perm_set_path(path, perm);
		kfree(path);
		break;
	}
	default: {
		ERR("Unknown file protect command");
	}
	}

response:

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		ERR("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_FILE_PROTECT);
	if (unlikely(!head)) {
		ERR("genlmsg_put_reply failed");
		goto errout;
	}

	if (info->attrs[FILE_A_SESSION]) {
		session = nla_get_s32(info->attrs[FILE_A_SESSION]);
		error = nla_put_s32(reply, FILE_A_SESSION, session);
		if (unlikely(error)) {
			ERR("nla_put_s32 failed");
			goto errout;
		}
	}

	error = nla_put_s32(reply, FILE_A_OP_TYPE, type);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, FILE_A_STATUS_CODE, code);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		ERR("genlmsg_reply failed");

	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}
