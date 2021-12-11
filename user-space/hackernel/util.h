#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif

EXTERN_C_BEGIN

#if defined(DEBUG)
#define LOG(fmt, arg...)                                                                                               \
    do {                                                                                                               \
        time_t now = time(NULL);                                                                                       \
        struct tm *t = localtime(&now);                                                                                \
        printf("[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,      \
               t->tm_hour, t->tm_min, t->tm_sec, __FILE__, __LINE__, ##arg);                                           \
        fflush(stdout);                                                                                                \
    } while (0)
#else
#define LOG(fmt, arg...)
#endif

int KernelModuleInsert(const char *filename);
int KernelModuleRemove(const char *modulename);

EXTERN_C_END

#endif
