#include "log.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

int init_hackernel(void)
{
	log("module_init\n");
	return 0;
}

void cleanup_hackernel(void)
{
	log("module_exit\n");
	return;
}

module_init(init_hackernel);
module_exit(cleanup_hackernel);
MODULE_AUTHOR("sugarmix");
MODULE_DESCRIPTION("sugarmix's kernel helper");
MODULE_LICENSE("GPL");
