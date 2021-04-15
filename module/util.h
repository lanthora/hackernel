#ifndef HACKERNEL_UTIL
#define HACKERNEL_UTIL

#include <linux/kernel.h>

// 需要使用变量的时候可以逐个获取，这个函数非不要不使用
int count_strings(const char *const *argv);

#endif