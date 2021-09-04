#ifndef HACKERNEL_DEFINE_H
#define HACKERNEL_DEFINE_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define NO_KALLSYMS_LOOKUP_NAME 1
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0))
#define NO_NLA_STRSCPY 1
#endif

#endif