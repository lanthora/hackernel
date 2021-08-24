#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#include <stdio.h>

#define LOG(fmt, arg...)                                                       \
  do {                                                                         \
    printf("%s:%d " fmt "\n", __FILE__, __LINE__, ##arg);                      \
    fflush(stdout);                                                            \
  } while (0)

int insmod(const char *filename);
int rmmod(const char *modulename);

#endif
