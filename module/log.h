#ifndef HACKERNEL_LOG
#define HACKERNEL_LOG

#include <linux/kernel.h>

#define log(fmt, arg...)                                                       \
	printk(KERN_INFO "[hackernel] %s:%d " fmt, __FUNCTION__, __LINE__,     \
	       ##arg)

#endif