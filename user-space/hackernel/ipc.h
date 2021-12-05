#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "hackernel/util.h"

namespace hackernel {

int IpcStart(void);
void IpcStop(void);

class Session {};

};  // namespace hackernel

#endif
