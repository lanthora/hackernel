#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "hackernel/util.h"

namespace hackernel {

int IpcWait(void);
void IpcExitNotify(void);

class Session {};

};  // namespace hackernel

#endif
