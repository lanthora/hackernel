/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_WATCHDOG_H
#define HACKERNEL_WATCHDOG_H

#include <linux/kernel.h>

bool conn_check_living(void);
void conn_check_set_alive(void);
void conn_check_set_dead(void);
void conn_check_init(void);
void conn_check_destory(void);

#endif
