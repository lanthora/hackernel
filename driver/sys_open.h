#ifndef HACKERNEL_SYS_OPEN
#define HACKERNEL_SYS_OPEN

#include "syscall.h"

int replace_open(void);
int restore_open(void);

#endif