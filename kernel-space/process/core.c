#include "netlink.h"
#include "process.h"
#include "syscall.h"
#include "util.h"
#include <linux/binfmts.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/types.h>

extern pid_t g_service_tgid;

struct nla_policy process_policy[PROCESS_A_MAX + 1] = {
	[PROCESS_A_STATUS_CODE] = { .type = NLA_S32 },
	[PROCESS_A_OP_TYPE] = { .type = NLA_U8 },
	[PROCESS_A_NAME] = { .type = NLA_STRING },
	[PROCESS_A_PERM] = { .type = NLA_S32 },
	[PROCESS_A_ID] = { .type = NLA_S32 },
};

DEFINE_HOOK(execve);
DEFINE_HOOK(execveat);

static DECLARE_WAIT_QUEUE_HEAD(process_perm_wq);
static atomic_t atomic_process_id = ATOMIC_INIT(0);

#define PROCESS_PERM_MASK 0xFF
#define PROCESS_PERM_SIZE (PROCESS_PERM_MASK + 1) // 256
#define PROCESS_PERM_HASH(id) (id & (PROCESS_PERM_MASK)) // 散列函数

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
		LOG("no memory");
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
	wake_up(&process_perm_wq);

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

static int process_perm_condition(process_perm_id_t id, process_perm_t *retval)
{
	*retval = process_perm_search(id);
	return *retval;
}

static process_perm_t process_protect_status(char *msg)
{
	int error;
	static process_perm_id_t id;
	process_perm_t retval = PROCESS_INVAILD;
	const unsigned long timeout = msecs_to_jiffies(100U);

	id = atomic_inc_return(&atomic_process_id);

	error = process_perm_insert(id);
	if (error) {
		LOG("process_perm_insert failed");
		goto out;
	}

	error = process_protect_report_to_userspace(id, msg);
	if (error) {
		LOG("process_protect_report_to_userspace failed");
		goto out;
	}

	wait_event_timeout(process_perm_wq, process_perm_condition(id, &retval),
			   timeout);

out:
	process_perm_delele(id);
	return retval;
}

static int sys_execveat_helper(int dirfd, char __user *pathname,
			       char __user *__user *argv,
			       char __user *__user *envp, int flag)
{
	char *msg = NULL;
	char *pwd = NULL;
	char *exec = NULL;
	char *cmd = NULL;

	int error = 0;
	process_perm_t perm = PROCESS_INVAILD;

	if (!g_portid)
		goto out;

	msg = kzalloc(MAX_ARG_STRLEN, GFP_KERNEL);
	if (!msg)
		goto out;

	pwd = get_pwd_path_alloc();
	if (!pwd)
		goto out;
	strcat(msg, pwd);

	exec = get_absolute_path_alloc(dirfd, pathname);
	if (!exec)
		goto out;
	strcat(msg, ASCII_US_STR);
	strcat(msg, exec);

	cmd = parse_argv_alloc((const char *const *)argv);
	if (!cmd)
		goto out;

	strcat(msg, ASCII_US_STR);
	strcat(msg, cmd);

	msg = adjust_path(msg);

	perm = process_protect_status(msg);
	if (perm == PROCESS_REJECT)
		error = -EPERM;

out:
	kfree(msg);
	kfree(pwd);
	kfree(exec);
	kfree(cmd);

	return error;
}

static asmlinkage long sys_execve_hook(struct pt_regs *regs)
{
	char *pathname = (char *)SC_ARG_1;
	char **argv = (char **)SC_ARG_2;
	char **envp = (char **)SC_ARG_3;

	if (sys_execveat_helper(AT_FDCWD, pathname, argv, envp, 0))
		return -EPERM;

	return hk_sys_execve(regs);
}

static asmlinkage long sys_execveat_hook(struct pt_regs *regs)
{
	int dirfd = (int)SC_ARG_1;
	char *pathname = (char *)SC_ARG_2;
	char **argv = (char **)SC_ARG_3;
	char **envp = (char **)SC_ARG_4;
	int flags = (int)SC_ARG_5;

	if (sys_execveat_helper(dirfd, pathname, argv, envp, flags))
		return -EPERM;

	return hk_sys_execveat(regs);
}

static int self_protect(pid_t nr, int sig)
{
	struct task_struct *task;
	struct pid *pid;

	if (nr <= 0)
		return 0;
	pid = find_get_pid(nr);
	if (!pid)
		return 0;
	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task)
		return 0;
	if (task->tgid != g_service_tgid)
		return 0;
	return -EPERM;
}

#define __MAP1(cnt, m, t, a, ...) m(t, a, cnt)
#define __MAP2(cnt, m, t, a, ...) m(t, a, cnt), __MAP1(cnt##i, m, __VA_ARGS__)
#define __MAP3(cnt, m, t, a, ...) m(t, a, cnt), __MAP2(cnt##i, m, __VA_ARGS__)
#define __MAP4(cnt, m, t, a, ...) m(t, a, cnt), __MAP3(cnt##i, m, __VA_ARGS__)
#define __MAP5(cnt, m, t, a, ...) m(t, a, cnt), __MAP4(cnt##i, m, __VA_ARGS__)
#define __MAP6(cnt, m, t, a, ...) m(t, a, cnt), __MAP5(cnt##i, m, __VA_ARGS__)

#if CONFIG_X86

#define __HOOK_DECL(t, a, cnt) t a
#define __HOOK_ARGS(t, a, cnt) a

#define DECL_MAP(n, ...) __MAP##n(i, __HOOK_DECL, __VA_ARGS__)
#define ARGS_MAP(n, ...) __MAP##n(i, __HOOK_ARGS, __VA_ARGS__)
#define DECL_MAP_RAW DECL_MAP
#define ARGS_MAP_RAW ARGS_MAP

#else

#define __HOOK_DECL(t, a, cnt) t a
#define __HOOK_ARGS(t, a, cnt) t SC_ARG_##cnt
#define DECL_MAP(n, ...) __MAP##n(i, __HOOK_DECL, __VA_ARGS__)
#define ARGS_MAP(n, ...) __MAP##n(i, __HOOK_ARGS, __VA_ARGS__)
#define DECL_MAP_RAW(n, ...) struct pt_regs *regs
#define ARGS_MAP_RAW(n, ...) regs

#endif

#define HOOK_DEFINEx(x, name, ...)                                             \
	static long __sys_##name##_hook(DECL_MAP(x, __VA_ARGS__));             \
	static long *hk_##name##_hook(DECL_MAP_RAW(x, __VA_ARGS__));           \
	long sys_##name##_hook(DECL_MAP_RAW(x, __VA_ARGS__))                   \
	{                                                                      \
		long retval;                                                   \
		retval = __sys_##name##_hook(ARGS_MAP(x, __VA_ARGS__));        \
		if (retval)                                                    \
			return retval;                                         \
		return hk_##name##_hook(ARGS_MAP_RAW(x, __VA_ARGS__));         \
	}

#define HOOK_DEFINE1(name, ...) HOOK_DEFINEx(1, name, __VA_ARGS__)
#define HOOK_DEFINE2(name, ...) HOOK_DEFINEx(2, name, __VA_ARGS__)
#define HOOK_DEFINE3(name, ...) HOOK_DEFINEx(3, name, __VA_ARGS__)
#define HOOK_DEFINE4(name, ...) HOOK_DEFINEx(4, name, __VA_ARGS__)
#define HOOK_DEFINE5(name, ...) HOOK_DEFINEx(5, name, __VA_ARGS__)
#define HOOK_DEFINE6(name, ...) HOOK_DEFINEx(6, name, __VA_ARGS__)

HOOK_DEFINE2(kill, pid_t, pid, int, sig)
{
	return 0;
}

int enable_process_protect(void)
{
	REG_HOOK(execve);
	REG_HOOK(execveat);
	REG_HOOK(kill);
	return 0;
}

int disable_process_protect(void)
{
	UNREG_HOOK(execve);
	UNREG_HOOK(execveat);
	UNREG_HOOK(kill);
	process_perm_hlist_clear();
	return 0;
}

int process_protect_init()
{
	return process_perm_hlist_init();
}

int process_protect_destory()
{
	return disable_process_protect();
}
