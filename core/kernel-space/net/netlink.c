/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/netlink.h"
#include "hackernel/handshake.h"
#include "hackernel/log.h"
#include "hackernel/net.h"
#include "hackernel/watchdog.h"

extern struct genl_family genl_family;

struct nla_policy net_policy[NET_A_MAX + 1] = {
	[NET_A_STATUS_CODE] = { .type = NLA_S32 },
	[NET_A_SESSION] = { .type = NLA_S32 },

	[NET_A_OP_TYPE] = { .type = NLA_U8 },
	[NET_A_ID] = { .type = NLA_S32 },
	[NET_A_PRIORITY] = { .type = NLA_S8 },
	[NET_A_ADDR_SRC_BEGIN] = { .type = NLA_U32 },
	[NET_A_ADDR_SRC_END] = { .type = NLA_U32 },
	[NET_A_ADDR_DST_BEGIN] = { .type = NLA_U32 },
	[NET_A_ADDR_DST_END] = { .type = NLA_U32 },
	[NET_A_PORT_SRC_BEGIN] = { .type = NLA_U16 },
	[NET_A_PORT_SRC_END] = { .type = NLA_U16 },
	[NET_A_PORT_DST_BEGIN] = { .type = NLA_U16 },
	[NET_A_PORT_DST_END] = { .type = NLA_U16 },
	[NET_A_PROTOCOL_BEGIN] = { .type = NLA_U8 },
	[NET_A_PROTOCOL_END] = { .type = NLA_U8 },
	[NET_A_RESPONSE] = { .type = NLA_U32 },
	[NET_A_FLAGS] = { .type = NLA_S32 },
};

static int net_protect_info_to_policy(const struct genl_info *info,
				      struct net_policy_t *policy)
{
	if (!info->attrs[NET_A_ID])
		return -EINVAL;
	if (!info->attrs[NET_A_PRIORITY])
		return -EINVAL;

	if (!info->attrs[NET_A_ADDR_SRC_BEGIN])
		return -EINVAL;
	if (!info->attrs[NET_A_ADDR_SRC_END])
		return -EINVAL;
	if (!info->attrs[NET_A_ADDR_DST_BEGIN])
		return -EINVAL;
	if (!info->attrs[NET_A_ADDR_DST_END])
		return -EINVAL;

	if (!info->attrs[NET_A_PORT_SRC_BEGIN])
		return -EINVAL;
	if (!info->attrs[NET_A_PORT_SRC_END])
		return -EINVAL;
	if (!info->attrs[NET_A_PORT_DST_BEGIN])
		return -EINVAL;
	if (!info->attrs[NET_A_PORT_DST_END])
		return -EINVAL;

	if (!info->attrs[NET_A_PROTOCOL_BEGIN])
		return -EINVAL;
	if (!info->attrs[NET_A_PROTOCOL_END])
		return -EINVAL;

	if (!info->attrs[NET_A_RESPONSE])
		return -EINVAL;

	if (!info->attrs[NET_A_FLAGS])
		return -EINVAL;

	policy->id = nla_get_s32(info->attrs[NET_A_ID]);
	policy->priority = nla_get_s8(info->attrs[NET_A_PRIORITY]);

	policy->addr.src.begin = nla_get_u32(info->attrs[NET_A_ADDR_SRC_BEGIN]);
	policy->addr.src.end = nla_get_u32(info->attrs[NET_A_ADDR_SRC_END]);
	policy->addr.dst.begin = nla_get_u32(info->attrs[NET_A_ADDR_DST_BEGIN]);
	policy->addr.dst.end = nla_get_u32(info->attrs[NET_A_ADDR_DST_END]);

	policy->port.src.begin = nla_get_u16(info->attrs[NET_A_PORT_SRC_BEGIN]);
	policy->port.src.end = nla_get_u16(info->attrs[NET_A_PORT_SRC_END]);
	policy->port.dst.begin = nla_get_u16(info->attrs[NET_A_PORT_DST_BEGIN]);
	policy->port.dst.end = nla_get_u16(info->attrs[NET_A_PORT_DST_END]);

	policy->protocol.begin = nla_get_u8(info->attrs[NET_A_PROTOCOL_BEGIN]);
	policy->protocol.end = nla_get_u8(info->attrs[NET_A_PROTOCOL_END]);

	policy->response = nla_get_u32(info->attrs[NET_A_RESPONSE]);
	policy->flags = nla_get_s32(info->attrs[NET_A_FLAGS]);

	return 0;
}

int net_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	struct net_policy_t policy;
	int error = 0;
	int code = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	u8 type;
	s32 session;

	if (hackernel_user_check(info))
		return -EPERM;

	if (!info->attrs[NET_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[NET_A_OP_TYPE]);
	switch (type) {
	case NET_PROTECT_ENABLE:
		code = net_protect_enable();
		goto response;
	case NET_PROTECT_DISABLE:
		code = net_protect_disable();
		goto response;
	case NET_PROTECT_INSERT:
		code = net_protect_info_to_policy(info, &policy);
		if (code)
			goto response;

		code = net_policy_insert(&policy);
		goto response;
	case NET_PROTECT_DELETE:
		if (!info->attrs[NET_A_ID]) {
			code = -EINVAL;
			goto response;
		}
		code = net_policy_delete(nla_get_s32(info->attrs[NET_A_ID]));
		goto response;
	case NET_PROTECT_CLEAR:
		code = net_policy_clear();
		goto response;
	default:
		ERR("Unknown process protect command");
	}

response:
	reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		ERR("genlmsg_new failed");
		goto out_free;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_NET_PROTECT);
	if (unlikely(!head)) {
		ERR("genlmsg_put_reply failed");
		goto out_free;
	}

	if (info->attrs[NET_A_SESSION]) {
		session = nla_get_s32(info->attrs[NET_A_SESSION]);
		error = nla_put_s32(reply, NET_A_SESSION, session);
		if (unlikely(error)) {
			ERR("nla_put_s32 failed");
			goto out_cancel;
		}
	}

	error = nla_put_u32(reply, NET_A_OP_TYPE, type);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
		goto out_cancel;
	}

	error = nla_put_s32(reply, NET_A_STATUS_CODE, code);
	if (unlikely(error)) {
		ERR("nla_put_s32 failed");
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

int net_protect_report_event(const struct net_event_t *event)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);

	if ((!skb)) {
		ERR("genlmsg_new failed");
		error = -ENOMEM;
		goto out_free;
	}

	head = genlmsg_put(skb, hackernel_portid, 0, &genl_family, 0,
			   HACKERNEL_C_NET_PROTECT);
	if (!head) {
		ERR("genlmsg_put failed");
		error = -ENOMEM;
		goto out_free;
	}
	error = nla_put_u8(skb, NET_A_OP_TYPE, NET_PROTECT_REPORT);
	if (error) {
		ERR("nla_put_u8 failed");
		goto out_cancel;
	}

	error = nla_put_u8(skb, NET_A_PROTOCOL_BEGIN, event->protocol);
	if (error) {
		ERR("nla_put_u32 failed");
		goto out_cancel;
	}

	error = nla_put_u32(skb, NET_A_ADDR_SRC_BEGIN, event->saddr);
	if (error) {
		ERR("nla_put_u32 failed");
		goto out_cancel;
	}

	error = nla_put_u32(skb, NET_A_ADDR_DST_BEGIN, event->daddr);
	if (error) {
		ERR("nla_put_u32 failed");
		goto out_cancel;
	}

	error = nla_put_u16(skb, NET_A_PORT_SRC_BEGIN, event->sport);
	if (error) {
		ERR("nla_put_u16 failed");
		goto out_cancel;
	}

	error = nla_put_u16(skb, NET_A_PORT_DST_BEGIN, event->dport);
	if (error) {
		ERR("nla_put_u16 failed");
		goto out_cancel;
	}

	error = nla_put_u32(skb, NET_A_ID, event->policy);
	if (error) {
		ERR("nla_put_u32 failed");
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
