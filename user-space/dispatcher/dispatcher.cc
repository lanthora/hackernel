#include "hackernel/dispatcher.h"
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"

namespace hackernel {

extern bool UserProcEnable(const std::string &msg);
extern bool UserProcDisable(const std::string &msg);
extern bool UserFileEnable(const std::string &msg);
extern bool UserFileDisable(const std::string &msg);
extern bool UserFileSet(const std::string &msg);
extern bool UserNetEnable(const std::string &msg);
extern bool UserNetDisable(const std::string &msg);
extern bool UserNetInsert(const std::string &msg);
extern bool UserNetDelete(const std::string &msg);

static std::shared_ptr<Receiver> dispatcher = nullptr;

int DispatcherWait() {
    ThreadNameUpdate("dispatcher");
    dispatcher = std::make_shared<Receiver>();

    dispatcher->AddHandler(UserProcEnable);
    dispatcher->AddHandler(UserProcDisable);
    dispatcher->AddHandler(UserFileEnable);
    dispatcher->AddHandler(UserFileDisable);
    dispatcher->AddHandler(UserFileSet);
    dispatcher->AddHandler(UserNetEnable);
    dispatcher->AddHandler(UserNetDisable);
    dispatcher->AddHandler(UserNetInsert);
    dispatcher->AddHandler(UserNetDelete);

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
