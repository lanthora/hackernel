#ifndef HACKERNEL_FILE_H
#define HACKERNEL_FILE_H

#include "syscall.h"

DEFINE_HOOK_HEADER(open);
DEFINE_HOOK_HEADER(openat);
DEFINE_HOOK_HEADER(unlinkat);
DEFINE_HOOK_HEADER(renameat2);

#endif