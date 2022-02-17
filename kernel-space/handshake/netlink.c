/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/netlink.h"
#include "hackernel/handshake.h"
#include "hackernel/syscall.h"
#include <net/genetlink.h>

extern struct genl_family genl_family;
struct nla_policy handshake_policy[HANDSHAKE_A_MAX + 1] = {
	[HANDSHAKE_A_STATUS_CODE] = { .type = NLA_S32 },
	[HANDSHAKE_A_SYS_SERVICE_TGID] = { .type = NLA_S32 },
};

int handshake_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	int code = 0;

	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		ERR("netlink_capable failed");
		return -EPERM;
	}

	if (hackernel_heartbeat_check(info)) {
		ERR("hackernel_heartbeat_check failed");
		return -EPERM;
	}

	if (!info->attrs[HANDSHAKE_A_SYS_SERVICE_TGID]) {
		code = -EINVAL;
		ERR("HANDSHAKE_A_SYS_SERVICE_TGID failed");
		goto response;
	}

	tgid_init(nla_get_s32(info->attrs[HANDSHAKE_A_SYS_SERVICE_TGID]));

response:
	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		ERR("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_HANDSHAKE);
	if (unlikely(!head)) {
		ERR("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_s32(reply, HANDSHAKE_A_STATUS_CODE, code);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	// reply指向的内存由 genlmsg_reply 释放
	// 此处调用 nlmsg_free(reply) 会引起内核crash
	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		ERR("genlmsg_reply failed");

	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}
