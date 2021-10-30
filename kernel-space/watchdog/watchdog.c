#include "watchdog.h"
#include "util.h"

static int watchdog_kthread(void *data)
{
	struct watchdog *dog = data;

	LOG("watchdog_kthread start");
	if (!dog || !dog->bark) {
		LOG("invalid watch dog");
		return 0;
	}
	while (!kthread_should_stop()) {
		LOG("watchdog_kthread sleep");
		sleep_jiffies(dog->timeout);
		if (time_is_after_jiffies(dog->last + dog->timeout)) {
			LOG("watch dog bark");
			dog->bark();
		}
	}
	LOG("watchdog_kthread exit");
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
	dog->task = kthread_run(watchdog_kthread, dog, "watchdog_kthread");
	if (IS_ERR(dog->task) || PTR_ERR(dog->task))
		LOG("watchdog_kthread create failed");
}

void watchdog_stop(struct watchdog *dog)
{
	if (!dog)
		return;
	if (IS_ERR(dog->task) || PTR_ERR(dog->task))
		return;
	kthread_stop(dog->task);
}
