/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/netlink.h"
#include "file/utils.h"
#include "hackernel/define.h"
#include "hackernel/file.h"
#include "hackernel/handshake.h"
#include "hackernel/log.h"
#include "hackernel/watchdog.h"
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
	[FILE_A_FLAG] = { .type = NLA_S32 },
	[FILE_A_FSID] = { .type = NLA_U64 },
	[FILE_A_INO] = { .type = NLA_U64 },
};

extern struct genl_family genl_family;

int file_protect_report_event(struct file_perm_data *data)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;
	const char *filename = data->path;
	const file_perm_t perm = data->marked_perm;
	const hkfsid_t fsid = data->fsid;
	const hkino_t ino = data->ino;

	if (!filename)
		ERR("filename is null");

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if ((!skb)) {
		ERR("genlmsg_new failed");
		error = -ENOMEM;
		goto out_free;
	}

	head = genlmsg_put(skb, hackernel_portid, 0, &genl_family, 0,
			   HACKERNEL_C_FILE_PROTECT);
	if (!head) {
		ERR("genlmsg_put failed");
		error = -ENOMEM;
		goto out_free;
	}
	error = nla_put_u8(skb, FILE_A_OP_TYPE, FILE_PROTECT_REPORT);
	if (error) {
		ERR("nla_put_u8 failed");
		goto out_cancel;
	}

	error = nla_put_s32(skb, FILE_A_PERM, perm);
	if (error) {
		ERR("nla_put_s32 failed");
		goto out_cancel;
	}

	error = nla_put(skb, FILE_A_FSID, sizeof(hkfsid_t), &fsid);
	if (error) {
		ERR("nla_put_u64 failed");
		goto out_cancel;
	}

	error = nla_put(skb, FILE_A_INO, sizeof(hkino_t), &ino);
	if (error) {
		ERR("nla_put_u64 failed");
		goto out_cancel;
	}

	error = nla_put_string(skb, FILE_A_NAME, filename);
	if (error) {
		ERR("nla_put_string failed");
		goto out_cancel;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(hackernel_net, skb, hackernel_portid);
	if (error) {
		ERR("genlmsg_unicast failed error=[%d]", error);
		conn_check_set_dead();
	}

	return 0;

out_cancel:
	genlmsg_cancel(skb, head);
out_free:
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
	file_perm_t perm;
	char *path;
	hkfsid_t fsid;
	hkino_t ino;
	int flag;

	if (hackernel_user_check(info))
		return -EPERM;

	if (!info->attrs[FILE_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[FILE_A_OP_TYPE]);
	switch (type) {
	case FILE_PROTECT_ENABLE:
		code = file_protect_enable();
		goto response;
	case FILE_PROTECT_DISABLE:
		code = file_protect_disable();
		goto response;
	case FILE_PROTECT_SET:
		if (!info->attrs[FILE_A_NAME]) {
			code = -EINVAL;
			goto response;
		}

		if (!info->attrs[FILE_A_PERM]) {
			code = -EINVAL;
			goto response;
		}

		if (!info->attrs[FILE_A_FLAG]) {
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
		flag = nla_get_s32(info->attrs[FILE_A_FLAG]);
		file_id_get(path, &fsid, &ino);
		code = file_perm_set(fsid, ino, perm, flag);
		kfree(path);
		break;
	case FILE_PROTECT_CLEAR:
		code = file_perm_tree_clear();
		goto response;
	default:
		ERR("Unknown file protect command");
	}

response:
	reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		ERR("genlmsg_new failed");
		goto out_free;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_FILE_PROTECT);
	if (unlikely(!head)) {
		ERR("genlmsg_put_reply failed");
		goto out_free;
	}

	if (info->attrs[FILE_A_SESSION]) {
		session = nla_get_s32(info->attrs[FILE_A_SESSION]);
		error = nla_put_s32(reply, FILE_A_SESSION, session);
		if (unlikely(error)) {
			ERR("nla_put_s32 failed");
			goto out_cancel;
		}
	}

	error = nla_put_s32(reply, FILE_A_OP_TYPE, type);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto out_cancel;
	}

	error = nla_put_s32(reply, FILE_A_STATUS_CODE, code);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto out_cancel;
	}

	error = nla_put(reply, FILE_A_FSID, sizeof(hkfsid_t), &fsid);
	if (error) {
		ERR("nla_put_u64 failed");
		goto out_cancel;
	}

	error = nla_put(reply, FILE_A_INO, sizeof(hkino_t), &ino);
	if (error) {
		ERR("nla_put_u64 failed");
		goto out_cancel;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		ERR("genlmsg_reply failed");

	return 0;

out_cancel:
	genlmsg_cancel(reply, head);
out_free:
	nlmsg_free(reply);
	return 0;
}
