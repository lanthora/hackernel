#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "broadcaster.h"
#include "hackernel/util.h"
#include <memory>
#include <string>

namespace hackernel {

int IpcWait();
void IpcExit();

class IpcServer {
public:
    static IpcServer &GetInstance();
    int Init();

    // 需要开两个线程,receiver_消费线程和socket接收消息的线程
    int StartWait();

    int Stop();

private:
    IpcServer() {}
    std::shared_ptr<Receiver> receiver_ = nullptr;
    bool running_;

private:
    int UnixDomainSocketWait();
};

}; // namespace hackernel

#endif
