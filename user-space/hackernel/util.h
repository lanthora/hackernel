#ifndef HACKERNEL_UTIL_H
#define HACKERNEL_UTIL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <stdbool.h>
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

#define ERR(fmt, arg...)                                                                                               \
    do {                                                                                                               \
        time_t now = time(NULL);                                                                                       \
        struct tm *t = localtime(&now);                                                                                \
        fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n", t->tm_year + 1900, t->tm_mon + 1,         \
                t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, __FILE__, __LINE__, ##arg);                              \
        fflush(stdout);                                                                                                \
    } while (0)

#define ThreadNameUpdate(name)                                                                                         \
    do {                                                                                                               \
        pthread_setname_np(pthread_self(), name);                                                                      \
    } while (0)

int KernelModuleInsert(const char *filename);
int KernelModuleRemove(const char *modulename);

// 将各个线程的运行状态设置为退出
void Shutdown();

// Wait类函数进入循环前, 退出条件变量用GlobalRunningGet函数初始化.
// 进程初始化过程中出现致命错误,将调用Shutdown关闭各个线程,
// 如果线程设置运行状态位的时间晚于Shutdown设置的时间,该线程会误认为系统正常并继续运行
bool GlobalRunningGet();

EXTERN_C_END

#endif
