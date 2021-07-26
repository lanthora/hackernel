#include "comlayer.h"

extern struct genl_family genl_family;

int handshake_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	unsigned long long syscall_table = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	int code;

	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		LOG("netlink_capable failed");
		return -EPERM;
	}

	if (!info->attrs[HANDSHAKE_A_SYS_CALL_TABLE_HEADER]) {
		code = -EINVAL;
		LOG("HANDSHAKE_A_SYS_CALL_TABLE_HEADER failed");
		goto response;
	}

	syscall_table =
		nla_get_u64(info->attrs[HANDSHAKE_A_SYS_CALL_TABLE_HEADER]);
	code = init_sys_call_table(syscall_table);
	portid = info->snd_portid;

response:
	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_HANDSHAKE);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_s32(reply, HANDSHAKE_A_STATUS_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	// reply指向的内存由 genlmsg_reply 释放
	// 此处调用 nlmsg_free(reply) 会引起内核crash
	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		LOG("genlmsg_reply failed");

	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}

int file_protect_report_to_userspace(struct file_perm_data *data)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;
	const char *filename = data->path;
	const file_perm_t perm = data->deny_perm;
	int errcnt;
	static atomic_t atomic_errcnt = ATOMIC_INIT(0);

	if (!filename)
		LOG("filename is null");

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if ((!skb)) {
		LOG("genlmsg_new failed");
		error = -ENOMEM;
		goto errout;
	}

	head = genlmsg_put(skb, portid, 0, &genl_family, 0,
			   HACKERNEL_C_FILE_PROTECT);
	if (!head) {
		LOG("genlmsg_put failed");
		error = -ENOMEM;
		goto errout;
	}
	error = nla_put_u8(skb, FILE_A_OP_TYPE, FILE_PROTECT_REPORT);
	if (error) {
		LOG("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, FILE_A_PERM, perm);
	if (error) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, FILE_A_NAME, filename);
	if (error) {
		LOG("nla_put_string failed");
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, portid);
	if (!error) {
		errcnt = atomic_xchg(&atomic_errcnt, 0);
		if (unlikely(errcnt))
			LOG("errcnt=[%u]", errcnt);

		goto out;
	}

	atomic_inc(&atomic_errcnt);

	if (error == -EAGAIN) {
		goto out;
	}

	portid = 0;
	LOG("genlmsg_unicast failed error=[%d]", error);

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
	u8 type;
	struct sk_buff *reply = NULL;
	void *head = NULL;

	if (portid != info->snd_portid)
		return -EPERM;

	if (!info->attrs[FILE_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[FILE_A_OP_TYPE]);
	switch (type) {
	case FILE_PROTECT_ENABLE: {
		code = enable_file_protect();
		goto response;
	}
	case FILE_PROTECT_DISABLE: {
		code = disable_file_protect();
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
		LOG("Unknown file protect command");
	}
	}

response:

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_FILE_PROTECT);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_s32(reply, FILE_A_OP_TYPE, type);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, FILE_A_STATUS_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		LOG("genlmsg_reply failed");

	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}

int process_protect_report_to_userspace(process_perm_id_t id, char *arg)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;
	int errcnt;
	static atomic_t atomic_errcnt = ATOMIC_INIT(0);

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if ((!skb)) {
		LOG("genlmsg_new failed");
		error = -ENOMEM;
		goto errout;
	}

	head = genlmsg_put(skb, portid, 0, &genl_family, 0,
			   HACKERNEL_C_PROCESS_PROTECT);
	if (!head) {
		LOG("genlmsg_put failed");
		error = -ENOMEM;
		goto errout;
	}
	error = nla_put_u8(skb, PROCESS_A_OP_TYPE, PROCESS_PROTECT_REPORT);
	if (error) {
		LOG("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, PROCESS_A_ID, id);
	if (error) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, PROCESS_A_NAME, arg);
	if (error) {
		LOG("nla_put_string failed");
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, portid);
	if (!error) {
		errcnt = atomic_xchg(&atomic_errcnt, 0);
		if (unlikely(errcnt))
			LOG("errcnt=[%u]", errcnt);

		goto out;
	}

	atomic_inc(&atomic_errcnt);

	if (error == -EAGAIN)
		goto out;

	portid = 0;
	LOG("genlmsg_unicast failed error=[%d]", error);

out:
	return 0;
errout:
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

	if (portid != info->snd_portid)
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
		code = enable_process_protect();
		goto response;
	}

	case PROCESS_PROTECT_DISABLE: {
		code = disable_process_protect();
		goto response;
	}
	default: {
		LOG("Unknown process protect command");
	}
	}

response:
	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_PROCESS_PROTECT);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_u32(reply, PROCESS_A_OP_TYPE, PROCESS_PROTECT_ENABLE);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, PROCESS_A_STATUS_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		LOG("genlmsg_reply failed");

out:
	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}

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

	if (!info->attrs[NET_A_ENABLED])
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
	policy->enabled = nla_get_s32(info->attrs[NET_A_ENABLED]);

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

	if (portid != info->snd_portid)
		return -EPERM;

	if (!info->attrs[NET_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[NET_A_OP_TYPE]);
	switch (type) {
	case NET_PROTECT_ENABLE:
		code = enable_net_protect();
		goto response;

	case NET_PROTECT_DISABLE:
		code = disable_net_protect();
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
	default: {
		LOG("Unknown process protect command");
	}
	}

response:
	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_NET_PROTECT);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_u32(reply, NET_A_OP_TYPE, type);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, NET_A_STATUS_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		LOG("genlmsg_reply failed");

	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}
