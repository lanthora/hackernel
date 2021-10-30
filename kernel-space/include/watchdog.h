#ifndef HACKERNEL_WATCHDOG_H
#define HACKERNEL_WATCHDOG_H

#include <generated/autoconf.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/sched.h>

#ifndef sleep_jiffies
#define sleep_jiffies(timeout)                                                 \
	do {                                                                   \
		long tmp = (long)timeout;                                      \
		while (tmp > 0 && !kthread_should_stop())                      \
			tmp = schedule_timeout(tmp);                           \
	} while (0);
#endif

struct watchdog {
	unsigned long last;
	unsigned long timeout;
	void (*bark)(void);
	struct task_struct *task;
};

void watchdog_feed(struct watchdog *dog);
void watchdog_start(struct watchdog *dog);
void watchdog_stop(struct watchdog *dog);

bool conn_check_living(void);
void conn_check_set_alive(void);
void conn_check_set_dead(void);
void conn_check_init(void);
void conn_check_destory(void);

#endif
