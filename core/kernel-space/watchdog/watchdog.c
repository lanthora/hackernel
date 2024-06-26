/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/log.h"
#include "watchdog/api.h"
#include <linux/jiffies.h>
#include <linux/kthread.h>

static int watchdog_kthread(void *data)
{
	struct watchdog *dog = data;

	if (!dog || !dog->bark) {
		ERR("invalid watch dog");
		return 0;
	}
	while (!kthread_should_stop()) {
		if (time_is_before_jiffies(dog->last + dog->timeout))
			dog->bark();
		schedule_timeout_interruptible(dog->timeout);
	}
	return 0;
}

void watchdog_feed(struct watchdog *dog)
{
	if (!dog)
		return;
	dog->last = jiffies;
}

void watchdog_start(struct watchdog *dog)
{
	dog->task = kthread_run(watchdog_kthread, dog, "watchdog/hackernel");
	if (IS_ERR_OR_NULL(dog->task)) {
		ERR("watchdog_kthread create failed");
		dog->task = NULL;
	}
}

void watchdog_stop(struct watchdog *dog)
{
	if (!dog || IS_ERR_OR_NULL(dog->task))
		return;
	kthread_stop(dog->task);
}
