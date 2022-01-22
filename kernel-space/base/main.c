/* SPDX-License-Identifier: GPL-2.0-only */
#include "file.h"
#include "net.h"
#include "netlink.h"
#include "process.h"
#include "util.h"
#include "watchdog.h"
#include <linux/module.h>

MODULE_LICENSE("GPL v2");

static int init(void)
{
	INFO("hackernel init");
	util_init();
	process_protect_init();
	file_protect_init();
	net_protect_init();
	conn_check_init();
	netlink_kernel_start();
	return 0;
}

static void cleanup(void)
{
	netlink_kernel_stop();
	conn_check_destory();
	process_protect_destory();
	file_protect_destory();
	net_protect_destory();
	INFO("hackernel exit");
	return;
}

module_init(init);
module_exit(cleanup);
