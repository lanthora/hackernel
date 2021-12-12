#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "broadcaster.h"
#include "hackernel/util.h"
#include <string>

namespace hackernel {

int IpcWait();
void IpcExit();

class IpcServer {
public:
    IpcServer GetInstance();
    int Init();

    // 需要开两个线程,receiver_消费线程和socket接收消息的线程
    int StartWait();

    int Stop(){
        running_ = false;
        receiver_.Exit();
        return 0;
    }

private:
    IpcServer() {}
    Receiver receiver_;
    bool running_;
};

}; // namespace hackernel

#endif
