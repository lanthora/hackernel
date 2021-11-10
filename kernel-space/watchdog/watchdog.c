/* SPDX-License-Identifier: GPL-2.0 */
#include "watchdog.h"
#include "util.h"

static int watchdog_kthread(void *data)
{
	struct watchdog *dog = data;

	if (!dog || !dog->bark) {
		LOG("invalid watch dog");
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
	dog->task = kthread_run(watchdog_kthread, dog, "hk_wdog");
	if (IS_ERR_OR_NULL(dog->task)) {
		LOG("watchdog_kthread create failed");
		dog->task = NULL;
	}
}

void watchdog_stop(struct watchdog *dog)
{
	if (!dog || IS_ERR_OR_NULL(dog->task))
		return;
	kthread_stop(dog->task);
}
