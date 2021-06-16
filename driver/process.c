#include "process.h"
#include "netlink.h"
#include "perm.h"
#include "syscall.h"
#include "util.h"
#include <asm/atomic.h>
#include <linux/binfmts.h>
#include <linux/gfp.h>
#include <linux/slab.h>

DEFINE_HOOK(execve);
DEFINE_HOOK(execveat);

static DECLARE_WAIT_QUEUE_HEAD(wq_process_perm);
static atomic_t atomic_process_id = ATOMIC_INIT(0);

static int process_protect_report_to_userspace(process_perm_id_t id, char *cmd)
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
	error = nla_put_u8(skb, HACKERNEL_A_TYPE, PROCESS_PROTECT_REPORT);
	if (error) {
		LOG("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, HACKERNEL_A_EXID, id);
	if (error) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, HACKERNEL_A_NAME, cmd);
	if (error) {
		LOG("nla_put_string failed");
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, portid);
	if (!error) {
		errcnt = atomic_read(&atomic_errcnt);
		if (unlikely(errcnt)) {
			LOG("atomic_errcnt=[%u]", errcnt);
			atomic_set(&atomic_errcnt, 0);
		}
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

static int condition_process_perm(process_perm_id_t id)
{
	return process_perm_search(id);
}

// 将execve的命令发送到用户态,用户态返回这条命令的执行权限
static process_perm_t process_protect_status(char *cmd)
{
	int error;
	static process_perm_id_t id;
	process_perm_t retval = PROCESS_INVAILD;
	const long timeout = msecs_to_jiffies(100U);

	id = atomic_inc_return(&atomic_process_id);

	error = process_perm_insert(id);
	if (error) {
		LOG("process_perm_insert failed");
		goto out;
	}

	error = process_protect_report_to_userspace(id, cmd);
	if (error) {
		LOG("process_protect_report_to_userspace failed");
		goto out;
	}
	// 进入等待队列
	wait_event_timeout(wq_process_perm, condition_process_perm(id),
			   timeout);

	// 从等待队列出来了
	retval = process_perm_search(id);

out:
	process_perm_delele(id);
	return retval;
}

static int sys_execveat_helper(int dirfd, char __user *pathname,
			       char __user *__user *argv,
			       char __user *__user *envp, int flag)
{
	char *cmd = NULL;
	int error = 0;
	process_perm_t perm = PROCESS_INVAILD;

	if (!portid) {
		goto out;
	}

	cmd = kzalloc(MAX_ARG_STRLEN, GFP_KERNEL);
	if (!cmd) {
		error = 0;
		goto out;
	}
	error = parse_argv((const char *const *)argv, cmd, MAX_ARG_STRLEN);
	if (error) {
		error = 0;
		goto out;
	}

	// 只有明确确定收到的是拒绝的情况下才拒绝
	// 其他情况要么是放行,要么是程序内部错误,都不应该拦截
	perm = process_protect_status(cmd);
	if (perm == PROCESS_REJECT) {
		error = -EPERM;
		goto out;
	}
	error = 0;
out:
	kfree(cmd);
	return error;
}

asmlinkage u64 sys_execve_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;

	if (sys_execveat_helper(AT_FDCWD, pathname, argv, envp, 0)) {
		return -EPERM;
	}
	return __x64_sys_execve(regs);
}

asmlinkage u64 sys_execveat_hook(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;
	char **argv = (char **)regs->dx;
	char **envp = (char **)regs->dx;
	int flags = (int)regs->r10;

	if (sys_execveat_helper(dirfd, pathname, argv, envp, flags)) {
		return -EPERM;
	}
	return __x64_sys_execveat(regs);
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
	case PROCESS_PROTECT_REPORT: {
		process_perm_id_t id;
		process_perm_t perm;
		id = nla_get_s32(info->attrs[HACKERNEL_A_EXID]);
		perm = nla_get_s32(info->attrs[HACKERNEL_A_PERM]);
		process_perm_update(id, perm);
		wake_up(&wq_process_perm);
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
out:
	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}
