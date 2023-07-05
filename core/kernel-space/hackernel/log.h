/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_LOG_H
#define HACKERNEL_LOG_H

#define ERR(fmt, arg...)                                                       \
	do {                                                                   \
		printk(KERN_ERR "hackernel: %s:%d " fmt "\n", __FILE__,        \
		       __LINE__, ##arg);                                       \
	} while (0)

#define INFO(fmt, arg...)                                                      \
	do {                                                                   \
		printk(KERN_INFO "hackernel: %s:%d " fmt "\n", __FILE__,       \
		       __LINE__, ##arg);                                       \
	} while (0)

#ifdef DEBUG
#define DBG(fmt, arg...)                                                       \
	do {                                                                   \
		printk(KERN_DEBUG "hackernel: %s:%d " fmt "\n", __FILE__,      \
		       __LINE__, ##arg);                                       \
	} while (0)
#else
#define DBG(fmt, arg...)
#endif

#endif
