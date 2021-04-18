#ifndef HACKERNEL_UTIL
#define HACKERNEL_UTIL

#include <linux/kernel.h>

int parse_pathname(const char __user *pathname, char *path, long size);
int parse_argv(const char __user *const __user *argv, char *params, long size);

#endif
