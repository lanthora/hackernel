#include "fperm.h"
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
	fperm_init();
	netlink_kernel_start();
	return 0;
}

static void cleanup(void)
{
	netlink_kernel_stop();
	disable_process_protect();
	disable_file_protect();
	fperm_destory();
	return;
}

module_init(init);
module_exit(cleanup);
