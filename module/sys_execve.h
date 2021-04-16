#ifndef HACKERNEL_SYS_EXECVE
#define HACKERNEL_SYS_EXECVE

#include "syscall.h"

int replace_execve(void);
int restore_execve(void);

#endif