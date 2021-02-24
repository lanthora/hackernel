#include "netlink.h"
#include "syscall.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("x");
MODULE_DESCRIPTION("kernel helper");

static int init(void)
{
	netlink_kernel_start();
	return 0;
}

static void cleanup(void)
{
	restore_sys_call();
	netlink_kernel_stop();
	return;
}

module_init(init);
module_exit(cleanup);
