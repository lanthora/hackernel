#include "netlink.h"
#include "perm.h"
#include "syscall.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("x");
MODULE_DESCRIPTION("kernel helper");

static int init(void)
{
	file_perm_init();
	process_perm_init();
	netlink_kernel_start();
	return 0;
}

static void cleanup(void)
{
	netlink_kernel_stop();
	process_perm_destory();
	disable_process_protect();
	disable_file_protect();
	file_perm_destory();
	return;
}

module_init(init);
module_exit(cleanup);
