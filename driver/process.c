#include "process.h"
#include "netlink.h"
#include "syscall.h"
#include "util.h"
#include <linux/binfmts.h>
#include <linux/gfp.h>
#include <linux/slab.h>

DEFINE_HOOK(execve);

static void notify_execve(char *cmd)
{
	int error;
	struct sk_buff *skb = NULL;
	void *head = NULL;

	if (!portid) {
		return;
	}
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if ((!skb)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put(skb, portid, 0, &genl_family, 0,
			   HACKERNEL_C_PROCESS_PROTECT);
	if (!head) {
		LOG("genlmsg_put failed");
		goto errout;
	}
	error = nla_put_u8(skb, HACKERNEL_A_TYPE, PROCESS_PROTECT_NOTIFY);
	if (error) {
		LOG("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_string(skb, HACKERNEL_A_NAME, cmd);
	if (error) {
		LOG("nla_put_string failed");
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, portid);
	if (error) {
		LOG("genlmsg_unicast failed");
		portid = 0;
	}
	return;

errout:
	nlmsg_free(skb);
	return;
}

static int sys_execve_hook(char __user *pathname, char __user *__user *argv,
			   char __user *__user *envp)
{
	char *cmd = NULL;
	int error = -1;

	cmd = kzalloc(MAX_ARG_STRLEN, GFP_KERNEL);
	if (!cmd) {
		error = -1;
		goto out;
	}
	error = parse_argv((const char *const *)argv, cmd, MAX_ARG_STRLEN);
	if (error) {
		goto out;
	}
	notify_execve(cmd);

out:
	kfree(cmd);
	return error;
}

asmlinkage u64 sys_execve_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;

	if (sys_execve_hook(pathname, argv, envp)) {
	}
	return __x64_sys_execve(regs);
}

int process_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	int code = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	u8 type;

	if (portid != info->snd_portid) {
		return -EPERM;
	}

	if (!info->attrs[HACKERNEL_A_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[HACKERNEL_A_TYPE]);
	switch (type) {
	case PROCESS_PROTECT_ENABLE: {
		code = enable_process_protect();
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

	error = nla_put_u32(reply, HACKERNEL_A_TYPE, PROCESS_PROTECT_ENABLE);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, HACKERNEL_A_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error)) {
		LOG("genlmsg_reply failed");
	}
	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}
