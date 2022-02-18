/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_LOG_H
#define HACKERNEL_LOG_H

#define ERR(fmt, arg...)                                                       \
	do {                                                                   \
		printk(KERN_ERR "hackernel: %s:%d " fmt "\n", __FILE__,        \
		       __LINE__, ##arg);                                       \
	} while (0)

#ifdef DEBUG
#define INFO(fmt, arg...)                                                      \
	do {                                                                   \
		printk(KERN_INFO "hackernel: %s:%d " fmt "\n", __FILE__,       \
		       __LINE__, ##arg);                                       \
	} while (0)
#else
#define INFO(fmt, arg...)
#endif

#endif
