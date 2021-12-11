#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "hackernel/util.h"
#include <stdint.h>

namespace hackernel {

const int32_t SYSTEM_SESSION_ID = 0;

int IpcWait(void);
void IpcExitNotify(void);

class Session {};

}; // namespace hackernel

#endif
