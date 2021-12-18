#include "hackernel/dispatcher.h"
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"

namespace hackernel {

extern bool UserProcEnable(const std::string &msg);
extern bool UserProcDisable(const std::string &msg);

static std::shared_ptr<Receiver> dispatcher = nullptr;

int DispatcherWait() {
    ThreadNameUpdate("dispatcher");
    dispatcher = std::make_shared<Receiver>();
    dispatcher->AddHandler(UserProcEnable);
    dispatcher->AddHandler(UserProcDisable);
    Broadcaster::GetInstance().AddReceiver(dispatcher);
    LOG("dispatcher enter");
    dispatcher->ConsumeWait();
    LOG("dispatcher exit");
    return 0;
}

void DispatcherExit() {
    if (dispatcher)
        dispatcher->Exit();
}

}; // namespace hackernel
