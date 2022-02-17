/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/netlink.h"
#include "hackernel/handshake.h"
#include "hackernel/process.h"
#include "hackernel/watchdog.h"
#include <linux/binfmts.h>

extern struct genl_family genl_family;
extern pid_t hackernel_tgid;

struct nla_policy process_policy[PROCESS_A_MAX + 1] = {
	[PROCESS_A_STATUS_CODE] = { .type = NLA_S32 },
	[PROCESS_A_SESSION] = { .type = NLA_S32 },

	[PROCESS_A_OP_TYPE] = { .type = NLA_U8 },
	[PROCESS_A_NAME] = { .type = NLA_STRING },
	[PROCESS_A_PERM] = { .type = NLA_S32 },
	[PROCESS_A_ID] = { .type = NLA_S32 },
};

int process_protect_report_to_userspace(process_perm_id_t id, char *cmd)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;
	int errcnt;
	static atomic_t atomic_errcnt = ATOMIC_INIT(0);

	skb = genlmsg_new(MAX_ARG_STRLEN, GFP_KERNEL);

	if (!skb) {
		ERR("genlmsg_new failed");
		error = -ENOMEM;
		goto errout;
	}

	head = genlmsg_put(skb, hackernel_portid, 0, &genl_family, 0,
			   HACKERNEL_C_PROCESS_PROTECT);
	if (!head) {
		ERR("genlmsg_put failed");
		error = -ENOMEM;
		goto errout;
	}
	error = nla_put_u8(skb, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
	if (error) {
		ERR("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, PROCESS_A_ID, id);
	if (error) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, PROCESS_A_NAME, cmd);
	if (error) {
		ERR("nla_put_string failed. errno=[%d]", error);
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, hackernel_portid);
	skb = NULL;
	if (error) {
		ERR("genlmsg_unicast failed error=[%d]", error);
		hackernel_portid = 0;
		hackernel_tgid = 0;
		conn_check_set_dead();
		atomic_inc(&atomic_errcnt);
		goto errout;
	}

	errcnt = atomic_xchg(&atomic_errcnt, 0);
	if (unlikely(errcnt))
		ERR("errcnt=[%u]", errcnt);

	return 0;
errout:
	if (skb)
		nlmsg_free(skb);

	return error;
}

int process_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	int code = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	u8 type;
	s32 session;

	if (hackernel_user_check(info))
		return -EPERM;

	if (!info->attrs[PROCESS_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[PROCESS_A_OP_TYPE]);
	switch (type) {
	case PROCESS_PROTECT_REPORT: {
		process_perm_id_t id;
		process_perm_t perm;
		id = nla_get_s32(info->attrs[PROCESS_A_ID]);
		perm = nla_get_s32(info->attrs[PROCESS_A_PERM]);
		process_perm_update(id, perm);
		goto out;
	}
	case PROCESS_PROTECT_ENABLE: {
		code = process_protect_enable();
		goto response;
	}

	case PROCESS_PROTECT_DISABLE: {
		code = process_protect_disable();
		goto response;
	}
	default: {
		ERR("Unknown process protect command");
	}
	}

response:
	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		ERR("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_PROCESS_PROTECT);
	if (unlikely(!head)) {
		ERR("genlmsg_put_reply failed");
		goto errout;
	}

	if (info->attrs[PROCESS_A_SESSION]) {
		session = nla_get_s32(info->attrs[PROCESS_A_SESSION]);
		error = nla_put_s32(reply, PROCESS_A_SESSION, session);
		if (unlikely(error)) {
			ERR("nla_put_s32 failed");
			goto errout;
		}
	}

	error = nla_put_u32(reply, PROCESS_A_OP_TYPE, type);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, PROCESS_A_STATUS_CODE, code);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		ERR("genlmsg_reply failed");

out:
	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}
