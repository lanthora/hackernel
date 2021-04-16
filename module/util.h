#ifndef HACKERNEL_UTIL
#define HACKERNEL_UTIL

#include <linux/kernel.h>

int count(char __user * __user *argv, int max);

#endif