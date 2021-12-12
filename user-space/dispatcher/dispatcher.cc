#include "hackernel/dispatcher.h"
#include "hackernel/broadcaster.h"

namespace hackernel {

extern bool KernelProcReport(const std::string &msg);
extern bool KernelProcStatus(const std::string &msg);

static std::shared_ptr<Receiver> dispatcher;

int DispatcherWait() {
    dispatcher = std::make_shared<Receiver>();
    dispatcher->AddHandler(KernelProcReport);
    dispatcher->AddHandler(KernelProcStatus);
    Broadcaster::GetInstance().AddReceiver(dispatcher);
    dispatcher->ConsumeWait();
    return 0;
}

void DispatcherExit() {
    dispatcher->ExitNotify();
}

}; // namespace hackernel
