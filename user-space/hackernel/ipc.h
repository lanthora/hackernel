#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "hackernel/util.h"
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdint.h>
#include <sys/un.h>

namespace hackernel {

int IpcWait();
void IpcExit();

}; // namespace hackernel

#endif
