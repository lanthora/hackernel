#include "netlink.h"
#include "syscall.h"
#include "util.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("x");
MODULE_DESCRIPTION("kernel helper");

static int init(void)
{
	LOG("module_init");
	netlink_kernel_start();
	return 0;
}

static void cleanup(void)
{
	netlink_kernel_stop();
	disable_process_protect();
	disable_file_protect();
	LOG("module_exit");
	return;
}

module_init(init);
module_exit(cleanup);
