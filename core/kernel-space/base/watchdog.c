/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/watchdog.h"
#include "watchdog/api.h"
#include <linux/jiffies.h>

static struct watchdog dog;
static bool connecting = false;

bool conn_check_living(void)
{
	return connecting;
}

void conn_check_set_alive(void)
{
	watchdog_feed(&dog);
	connecting = true;
}

void conn_check_set_dead(void)
{
	connecting = false;
}

void conn_check_init(void)
{
	dog.bark = conn_check_set_dead;
	dog.last = INITIAL_JIFFIES;
	dog.timeout = msecs_to_jiffies(3000U);
	watchdog_start(&dog);
}

void conn_check_destory(void)
{
	watchdog_stop(&dog);
}
