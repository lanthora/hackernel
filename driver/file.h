#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"

int replace_open(void);
int restore_open(void);

int replace_openat(void);
int restore_openat(void);

int replace_unlinkat(void);
int restore_unlinkat(void);

int replace_renameat2(void);
int restore_renameat2(void);

#define PATH_MIN 64

#endif