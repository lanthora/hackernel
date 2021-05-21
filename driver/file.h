#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"

int replace_open(void);
int restore_open(void);

int replace_openat(void);
int restore_openat(void);

int replace_unlinkat(void);
int restore_unlinkat(void);

#define PATH_MIN 32

#endif