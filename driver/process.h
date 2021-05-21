#ifndef HACKERNEL_PROCESS_H
#define HACKERNEL_PROCESS_H

#include "syscall.h"

int replace_execve(void);
int restore_execve(void);

#endif