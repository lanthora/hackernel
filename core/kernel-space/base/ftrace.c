/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/syscall.h"

#if HACKERNEL_USE_FTRACE
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

static DEFINE_MUTEX(hook_mutex);

#if defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
/*
 * Only redirect here. Policy evaluation and sleeping take place after the
 * trampoline has returned, in the replacement's normal syscall context.
 */
static void notrace hk_ftrace_redirect(unsigned long ip, unsigned long parent_ip,
				       struct ftrace_ops *ops,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
				       struct ftrace_regs *fregs)
#else
				       struct pt_regs *regs)
#endif
{
	struct hk_ftrace_hook *hook = container_of(ops, struct hk_ftrace_hook, ops);

	/* Calls from our wrappers to the original must not be redirected again. */
	if (within_module(parent_ip, THIS_MODULE))
		return;

	/* Count before redirecting, including tasks preempted before wrapper entry. */
	atomic_inc(&hook->active);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#ifdef ftrace_regs_set_instruction_pointer
	ftrace_regs_set_instruction_pointer(fregs, (unsigned long)hook->replacement);
#else
	instruction_pointer_set(ftrace_get_regs(fregs),
				(unsigned long)hook->replacement);
#endif
#else
	instruction_pointer_set(regs, (unsigned long)hook->replacement);
#endif
}
#endif

int hk_ftrace_register(struct hk_ftrace_hook *hook, void **original)
{
#if defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
	int error = 0;

	mutex_lock(&hook_mutex);
	if (hook->registered)
		goto out;
	if (!hk_kallsyms_lookup_name) {
		error = -ENOENT;
		goto out;
	}
	hook->address = hk_kallsyms_lookup_name(hook->symbol);
	if (!hook->address) {
		error = -ENOENT;
		goto out;
	}
	/* A live registration must be disabled before the module can be removed. */
	if (!try_module_get(THIS_MODULE)) {
		error = -ENODEV;
		goto out;
	}

	/* Publish the original before register_ftrace_function can redirect. */
	*original = (void *)hook->address;
	atomic_set(&hook->active, 0);
	init_waitqueue_head(&hook->drained);
	hook->ops.func = hk_ftrace_redirect;
	hook->ops.flags |= FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
	error = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (error)
		goto free_filter;
	error = register_ftrace_function(&hook->ops);
	if (error)
		goto free_filter;
	hook->registered = true;
	INFO("ftrace registered symbol=[%s]", hook->symbol);
	goto out;

free_filter:
	ftrace_free_filter(&hook->ops);
	module_put(THIS_MODULE);
out:
	mutex_unlock(&hook_mutex);
	return error;
#else
	ERR("ftrace requires CONFIG_DYNAMIC_FTRACE_WITH_REGS=y");
	return -EOPNOTSUPP;
#endif
}

int hk_ftrace_unregister(struct hk_ftrace_hook *hook)
{
#if defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
	int error = 0;

	mutex_lock(&hook_mutex);
	if (!hook->registered)
		goto out;
	error = unregister_ftrace_function(&hook->ops);
	if (error)
		goto out;
	hook->registered = false;

	/* Unregister stops callbacks, not sleeping replacement functions. */
	wait_event(hook->drained, !atomic_read(&hook->active));
	/* Drain the wrapper's final instructions after its active decrement. */
	synchronize_rcu_tasks();
	ftrace_free_filter(&hook->ops);
	INFO("ftrace unregistered symbol=[%s]", hook->symbol);
	module_put(THIS_MODULE);
out:
	mutex_unlock(&hook_mutex);
	return error;
#else
	return 0;
#endif
}

void hk_ftrace_exit(struct hk_ftrace_hook *hook)
{
	if (atomic_dec_and_test(&hook->active))
		wake_up(&hook->drained);
}
#endif
