/* SPDX-License-Identifier: GPL-2.0-only */
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

#define WARN(fmt, arg...)                                                                                              \
    do {                                                                                                               \
        time_t now = time(NULL);                                                                                       \
        struct tm *t = localtime(&now);                                                                                \
        fprintf(stdout, "[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n", t->tm_year + 1900, t->tm_mon + 1,         \
                t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, __FILE__, __LINE__, ##arg);                              \
        fflush(stdout);                                                                                                \
    } while (0)

#if defined(DEBUG)
#define LOG WARN
#else
#define LOG(fmt, arg...)
#endif

#define ERR(fmt, arg...)                                                                                               \
    do {                                                                                                               \
        time_t now = time(NULL);                                                                                       \
        struct tm *t = localtime(&now);                                                                                \
        fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n", t->tm_year + 1900, t->tm_mon + 1,         \
                t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, __FILE__, __LINE__, ##arg);                              \
        fflush(stderr);                                                                                                \
    } while (0)

#define ThreadNameUpdate(name)                                                                                         \
    do {                                                                                                               \
        pthread_setname_np(pthread_self(), name);                                                                      \
    } while (0)

int KernelModuleInsert(const char *filename);
int KernelModuleRemove(const char *modulename);

// 将各个线程的运行状态设置为退出
enum {
    HACKERNEL_SUCCESS,
    HACKERNEL_SIG,
    HACKERNEL_NETLINK_INIT,
    HACKERNEL_HEARTBEAT,
    HACKERNEL_NETLINK_WAIT,
    HACKERNEL_UNIX_DOMAIN_SOCKET,
    HACKERNEL_BAD_RECEIVER,
};

void SHUTDOWN(int code);

// Wait类函数进入循环前, 退出条件变量用RUNNING函数初始化.
// 进程初始化过程中出现致命错误,将调用SHUTDOWN关闭各个线程
bool RUNNING();

EXTERN_C_END

#endif
