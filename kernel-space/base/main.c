#include "file.h"
#include "net.h"
#include "netlink.h"
#include "process.h"
#include "util.h"
#include <linux/module.h>

MODULE_LICENSE("GPL v2");

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
	disable_net_protect();
	LOG("module_exit");
	return;
}

module_init(init);
module_exit(cleanup);
