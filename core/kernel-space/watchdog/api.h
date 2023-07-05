/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_WATCHDOG_API_H
#define HACKERNEL_WATCHDOG_API_H

#include <linux/sched.h>

struct watchdog {
	unsigned long last;
	unsigned long timeout;
	void (*bark)(void);
	struct task_struct *task;
};

void watchdog_feed(struct watchdog *dog);
void watchdog_start(struct watchdog *dog);
void watchdog_stop(struct watchdog *dog);

#endif
