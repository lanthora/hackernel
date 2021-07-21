#include "process.h"
#include "netlink.h"
#include "syscall.h"
#include "util.h"
#include <asm/atomic.h>
#include <linux/binfmts.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/types.h>

DEFINE_HOOK(execve);
DEFINE_HOOK(execveat);

static DECLARE_WAIT_QUEUE_HEAD(wq_process_perm);
static atomic_t atomic_process_id = ATOMIC_INIT(0);

// 由于id是逐一增加的,取余可以平均分配地址空间,由于散列函数的特殊实现,哈希表大小需要是2的整数次幂
#define PROCESS_PERM_MASK 0xFF
#define PROCESS_PERM_SIZE (PROCESS_PERM_MASK + 1) // 256
#define PROCESS_PERM_HASH(id) (id & (PROCESS_PERM_MASK)) // 散列函数

struct process_perm_node {
	struct hlist_node node;
	process_perm_id_t id;
	process_perm_t perm;
};

typedef struct process_perm_node process_perm_node_t;

struct process_perm_head {
	struct hlist_head head;
	rwlock_t lock;
};

typedef struct process_perm_head process_perm_head_t;

static void process_perm_head_init(process_perm_head_t *perm_head)
{
	INIT_HLIST_HEAD(&perm_head->head);
	rwlock_init(&perm_head->lock);
}

process_perm_head_t *process_perm_hlist;

static int process_perm_init(void)
{
	int idx;
	const size_t size = sizeof(process_perm_head_t) * PROCESS_PERM_SIZE;
	// hlist初始化方式就是将内存中的变量设置为NULL,kzalloc可以达到相同的效果
	if (process_perm_hlist)
		return -EPERM;

	process_perm_hlist = kmalloc(size, GFP_KERNEL);
	for (idx = 0; idx < PROCESS_PERM_SIZE; ++idx)
		process_perm_head_init(&process_perm_hlist[idx]);

	return 0;
}

static void process_perm_hlist_node_destory(process_perm_head_t *perm_head)
{
	struct process_perm_node *pos;
	struct hlist_node *n;
	write_lock(&perm_head->lock);
	hlist_for_each_entry_safe (pos, n, &perm_head->head, node) {
		hlist_del(&pos->node);
		kfree(pos);
	}
	write_unlock(&perm_head->lock);
}

static int process_perm_destory(void)
{
	size_t idx;
	if (!process_perm_hlist)
		return -EPERM;

	for (idx = 0; idx < PROCESS_PERM_SIZE; ++idx)
		process_perm_hlist_node_destory(&process_perm_hlist[idx]);

	kfree(process_perm_hlist);
	process_perm_hlist = NULL;
	return 0;
}

static int process_perm_insert(const process_perm_id_t id)
{
	const size_t size = sizeof(process_perm_node_t);
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];
	process_perm_node_t *new = kmalloc(size, GFP_KERNEL);

	new->id = id;
	new->perm = PROCESS_WATT;

	write_lock(&perm_head->lock);
	hlist_add_head(&new->node, &perm_head->head);
	write_unlock(&perm_head->lock);
	return 0;
}

static int process_perm_update(const process_perm_id_t id,
			       const process_perm_t perm)
{
	struct process_perm_node *pos;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];

	write_lock(&perm_head->lock);
	hlist_for_each_entry (pos, &perm_head->head, node) {
		if (pos->id != id)
			continue;

		pos->perm = perm;
		break;
	}
	write_unlock(&perm_head->lock);
	return 0;
}

static process_perm_t process_perm_search(const process_perm_id_t id)
{
	struct process_perm_node *pos;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];
	process_perm_t perm = PROCESS_INVAILD;

	read_lock(&perm_head->lock);
	hlist_for_each_entry (pos, &perm_head->head, node) {
		if (pos->id != id)
			continue;

		perm = pos->perm;
		break;
	}
	read_unlock(&perm_head->lock);
	return perm;
}

static int process_perm_delele(const process_perm_id_t id)
{
	struct process_perm_node *victim;
	struct hlist_node *n;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];

	write_lock(&perm_head->lock);
	hlist_for_each_entry_safe (victim, n, &perm_head->head, node) {
		if (victim->id != id)
			continue;

		hlist_del(&victim->node);
		kfree(victim);
		break;
	}
	write_unlock(&perm_head->lock);
	return 0;
}

static int process_protect_report_to_userspace(process_perm_id_t id, char *arg)
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
	error = nla_put_u8(skb, HACKERNEL_A_OP_TYPE, PROCESS_PROTECT_REPORT);
	if (error) {
		LOG("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, HACKERNEL_A_EXECVE_ID, id);
	if (error) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, HACKERNEL_A_NAME, arg);
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

static int condition_process_perm(process_perm_id_t id)
{
	return process_perm_search(id);
}

// 将execve的命令发送到用户态,用户态返回这条命令的执行权限
static process_perm_t process_protect_status(char *arg)
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

	error = process_protect_report_to_userspace(id, arg);
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
	char *cmd, *arg, *msg;
	int error = 0;
	process_perm_t perm = PROCESS_INVAILD;

	if (!portid)
		goto out;

	msg = kzalloc(MAX_ARG_STRLEN, GFP_KERNEL);

	cmd = get_absolute_path_alloc(dirfd, pathname);
	strcat(msg, cmd);
	kfree(cmd);

	arg = kzalloc(MAX_ARG_STRLEN, GFP_KERNEL);
	error = parse_argv((const char *const *)argv, arg, MAX_ARG_STRLEN);
	if (error) {
		error = 0;
		goto out;
	}
	if (arg[0]) {
		strcat(msg, ASCII_US_STR);
		strcat(msg, arg);
	}

	kfree(arg);

	msg = adjust_path(msg);

	// 只有明确确定收到的是拒绝的情况下才拒绝
	// 其他情况要么是放行,要么是程序内部错误,都不应该拦截
	perm = process_protect_status(msg);
	if (perm == PROCESS_REJECT) {
		error = -EPERM;
		goto out;
	}
	error = 0;
out:
	kfree(msg);
	return error;
}

static asmlinkage u64 sys_execve_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	char **argv = (char **)regs->si;
	char **envp = (char **)regs->dx;

	if (sys_execveat_helper(AT_FDCWD, pathname, argv, envp, 0))
		return -EPERM;

	return __x64_sys_execve(regs);
}

static asmlinkage u64 sys_execveat_hook(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;
	char **argv = (char **)regs->dx;
	char **envp = (char **)regs->dx;
	int flags = (int)regs->r10;

	if (sys_execveat_helper(dirfd, pathname, argv, envp, flags))
		return -EPERM;

	return __x64_sys_execveat(regs);
}
static int enable_process_protect(void)
{
	process_perm_init();
	REG_HOOK(execve);
	REG_HOOK(execveat);
	return 0;
}

static int disable_process_protect(void)
{
	UNREG_HOOK(execve);
	UNREG_HOOK(execveat);
	process_perm_destory();
	return 0;
}

void exit_process_protect(void)
{
	disable_process_protect();
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

	if (!info->attrs[HACKERNEL_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[HACKERNEL_A_OP_TYPE]);
	switch (type) {
	case PROCESS_PROTECT_REPORT: {
		process_perm_id_t id;
		process_perm_t perm;
		id = nla_get_s32(info->attrs[HACKERNEL_A_EXECVE_ID]);
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

	error = nla_put_u32(reply, HACKERNEL_A_OP_TYPE, PROCESS_PROTECT_ENABLE);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, HACKERNEL_A_STATUS_CODE, code);
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
