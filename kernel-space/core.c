#include "file.h"
#include "net.h"
#include "netlink.h"
#include "process.h"
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
	exit_process_protect();
	exit_file_protect();
	exit_net_protect();
	LOG("module_exit");
	return;
}

module_init(init);
module_exit(cleanup);
