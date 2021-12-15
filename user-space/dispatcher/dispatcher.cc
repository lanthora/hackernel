#include "hackernel/dispatcher.h"
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"

namespace hackernel {

extern bool KernelProcReport(const std::string &msg);
extern bool UserProcEnable(const std::string &msg);
extern bool UserProcDisable(const std::string &msg);

static std::shared_ptr<Receiver> dispatcher = nullptr;

int DispatcherWait() {
    ThreadNameUpdate("dispatcher");
    dispatcher = std::make_shared<Receiver>();
    dispatcher->AddHandler(KernelProcReport);
    dispatcher->AddHandler(UserProcEnable);
    dispatcher->AddHandler(UserProcDisable);
    Broadcaster::GetInstance().AddReceiver(dispatcher);
    dispatcher->ConsumeWait();
    return 0;
}

void DispatcherExit() {
    if (dispatcher)
        dispatcher->Exit();
}

}; // namespace hackernel
