#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#include <stdio.h>
#include <time.h>

#define LOG(fmt, arg...)                                                       \
  do {                                                                         \
    time_t now = time(NULL);                                                   \
    struct tm *t = localtime(&now);                                            \
    printf("[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n",                \
           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour,           \
           t->tm_min, t->tm_sec, __FILE__, __LINE__, ##arg);                   \
    fflush(stdout);                                                            \
  } while (0)

int InsertKernelModule(const char *filename);
int RemovekernelModule(const char *modulename);

#endif
