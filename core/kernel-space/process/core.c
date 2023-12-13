/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/utils.h"
#include "hackernel/handshake.h"
#include "hackernel/log.h"
#include "hackernel/netlink.h"
#include "hackernel/process.h"
#include "hackernel/syscall.h"
#include "hackernel/watchdog.h"
#include "process/utils.h"
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/types.h>

extern pid_t hackernel_tgid;

static DECLARE_WAIT_QUEUE_HEAD(wq);
static atomic_t atomic_process_id = ATOMIC_INIT(0);

#define PROCESS_PERM_MASK 0xFF
#define PROCESS_PERM_SIZE (PROCESS_PERM_MASK + 1) /* 256 */
#define PROCESS_PERM_HASH(id) (id & (PROCESS_PERM_MASK)) /* 散列函数 */

static process_perm_head_t process_perm_hlist[PROCESS_PERM_SIZE];
static DEFINE_RWLOCK(process_perm_hlist_lock);

static void process_perm_hlist_node_init(process_perm_head_t *perm_head)
{
	INIT_HLIST_HEAD(&perm_head->head);
	/* 读写锁需要运行时初始化 */
	rwlock_init(&perm_head->lock);
}

static int process_perm_hlist_init(void)
{
	int idx;

	write_lock(&process_perm_hlist_lock);
	for (idx = 0; idx < PROCESS_PERM_SIZE; ++idx)
		process_perm_hlist_node_init(&process_perm_hlist[idx]);
	write_unlock(&process_perm_hlist_lock);

	return 0;
}

static void process_perm_hlist_node_clear(process_perm_head_t *perm_head)
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

static int process_perm_hlist_clear(void)
{
	size_t idx;

	write_lock(&process_perm_hlist_lock);
	for (idx = 0; idx < PROCESS_PERM_SIZE; ++idx)
		process_perm_hlist_node_clear(&process_perm_hlist[idx]);
	write_unlock(&process_perm_hlist_lock);

	return 0;
}

static int process_perm_insert(const process_perm_id_t id)
{
	const size_t size = sizeof(process_perm_node_t);
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head;
	process_perm_node_t *new;

	read_lock(&process_perm_hlist_lock);

	perm_head = &process_perm_hlist[idx];
	new = kmalloc(size, GFP_KERNEL);
	if (!new) {
		ERR("no memory");
		goto out;
	}
	new->id = id;
	new->perm = PROCESS_WATT;

	write_lock(&perm_head->lock);
	hlist_add_head(&new->node, &perm_head->head);
	write_unlock(&perm_head->lock);
out:
	read_unlock(&process_perm_hlist_lock);
	return 0;
}

int process_perm_update(const process_perm_id_t id, const process_perm_t perm)
{
	struct process_perm_node *pos;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head;

	read_lock(&process_perm_hlist_lock);

	perm_head = &process_perm_hlist[idx];

	write_lock(&perm_head->lock);
	hlist_for_each_entry (pos, &perm_head->head, node) {
		if (pos->id != id)
			continue;

		pos->perm = perm;
		break;
	}
	write_unlock(&perm_head->lock);

	read_unlock(&process_perm_hlist_lock);
	wake_up(&wq);

	return 0;
}

static process_perm_t process_perm_search(const process_perm_id_t id)
{
	struct process_perm_node *pos;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_t perm = PROCESS_INVAILD;
	process_perm_head_t *perm_head;

	read_lock(&process_perm_hlist_lock);

	perm_head = &process_perm_hlist[idx];

	read_lock(&perm_head->lock);
	hlist_for_each_entry (pos, &perm_head->head, node) {
		if (pos->id != id)
			continue;

		perm = pos->perm;
		break;
	}
	read_unlock(&perm_head->lock);

	read_unlock(&process_perm_hlist_lock);
	return perm;
}

static int process_perm_delele(const process_perm_id_t id)
{
	struct process_perm_node *victim;
	struct hlist_node *n;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head;

	read_lock(&process_perm_hlist_lock);

	perm_head = &process_perm_hlist[idx];

	write_lock(&perm_head->lock);
	hlist_for_each_entry_safe (victim, n, &perm_head->head, node) {
		if (victim->id != id)
			continue;

		hlist_del(&victim->node);
		kfree(victim);
		break;
	}
	write_unlock(&perm_head->lock);

	read_unlock(&process_perm_hlist_lock);
	return 0;
}

static int process_perm_cond(process_perm_id_t id, process_perm_t *retval)
{
	*retval = process_perm_search(id);
	return *retval;
}

static process_perm_t process_protect_status(struct process_cmd_context *ctx)
{
	int error;
	process_perm_t retval = PROCESS_INVAILD;
	const unsigned long timeout = msecs_to_jiffies(100U);

	ctx->id = atomic_inc_return(&atomic_process_id);

	error = process_perm_insert(ctx->id);
	if (error) {
		ERR("process_perm_insert failed");
		goto out;
	}

	error = process_protect_report_event(ctx);
	if (error) {
		ERR("report to userspace failed");
		goto out;
	}

	wait_event_timeout(wq, process_perm_cond(ctx->id, &retval), timeout);

	if (retval == PROCESS_WATT) {
		ERR("get process protect status timeout");
		goto out;
	}

out:
	process_perm_delele(ctx->id);
	return retval;
}

static int sys_execveat_helper(int dirfd, char __user *pathname,
			       char __user *__user *argv,
			       char __user *__user *envp, int flag)
{
	struct process_cmd_context ctx = {};
	int error = 0;
	process_perm_t perm = PROCESS_INVAILD;

	if (!conn_check_living())
		goto out;

	if (hackernel_trusted_proccess())
		goto out;

	ctx.workdir = get_pwd_path_alloc();
	if (!ctx.workdir)
		goto out;

	ctx.binary = get_absolute_path_alloc(dirfd, pathname);
	if (!ctx.binary)
		goto out;

	ctx.argv = parse_argv_alloc((const char *const *)argv);
	if (!ctx.argv)
		goto out;

	perm = process_protect_status(&ctx);
	if (perm == PROCESS_REJECT)
		error = -EPERM;

out:
	kfree(ctx.workdir);
	kfree(ctx.binary);
	kfree(ctx.argv);

	return error;
}

static bool is_server_process(pid_t nr)
{
	struct task_struct *task = NULL;
	struct pid *pid = NULL;
	int retval = false;

	if (nr <= 0)
		goto out;
	pid = find_get_pid(nr);
	if (!pid)
		goto out;

	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task)
		goto out;

	if (task->tgid != hackernel_tgid)
		goto out;
	retval = true;
out:
	if (pid)
		put_pid(pid);
	if (task)
		put_task_struct(task);
	return retval;
}

static int self_protect(pid_t nr, int sig)
{
	if (!conn_check_living())
		return 0;

	if (!is_server_process(nr))
		return 0;

	if (sig == SIGKILL || sig == SIGSTOP)
		return -EPERM;
	return 0;
}

HOOK_DEFINE3(execve, char *, pathname, char **, argv, char **, envp)
{
	if (sys_execveat_helper(AT_FDCWD, pathname, argv, envp, 0))
		return -EPERM;
	return 0;
}

HOOK_DEFINE5(execveat, int, dirfd, char *, pathname, char **, argv, char **,
	     envp, int, flags)
{
	if (sys_execveat_helper(dirfd, pathname, argv, envp, flags))
		return -EPERM;
	return 0;
}

HOOK_DEFINE2(kill, pid_t, pid, int, sig)
{
	if (self_protect(pid, sig))
		return -EPERM;
	return 0;
}

HOOK_DEFINE2(delete_module, const char *, name, unsigned int, flags)
{
	if (strstarts(name, "hackernel"))
		return -EPERM;
	return 0;
}

int process_protect_enable(void)
{
	REG_HOOK(execve);
	REG_HOOK(execveat);
	REG_HOOK(kill);
	REG_HOOK(delete_module);
	return 0;
}

int process_protect_disable(void)
{
	UNREG_HOOK(execve);
	UNREG_HOOK(execveat);
	UNREG_HOOK(kill);
	UNREG_HOOK(delete_module);
	process_perm_hlist_clear();
	return 0;
}

int process_protect_init(void)
{
	return process_perm_hlist_init();
}

int process_protect_destory(void)
{
	return process_protect_disable();
}
