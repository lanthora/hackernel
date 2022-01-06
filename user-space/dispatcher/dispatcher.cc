/* SPDX-License-Identifier: GPL-2.0 */
#include "hackernel/dispatcher.h"
#include "dispatcher/handler.h"
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"

namespace hackernel {

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
