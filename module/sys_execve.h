#ifndef HACKERNEL_SYS_EXECVE
#define HACKERNEL_SYS_EXECVE

#include "syscall.h"

#define PATH_SIZE 512
#define BUFFSIZE 4096

int replace_execve(void);
int restore_execve(void);

#endif