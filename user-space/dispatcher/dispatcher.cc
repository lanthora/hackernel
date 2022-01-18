/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/dispatcher.h"
#include "dispatcher/handler.h"
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <unordered_set>

namespace hackernel {

static std::shared_ptr<Receiver> dispatcher = nullptr;
static std::unordered_set<std::string> dispatcher_concerned_types;

static void DispatcherFilterInit() {
    dispatcher_concerned_types.clear();
    dispatcher_concerned_types.insert("user::proc::enable");
    dispatcher_concerned_types.insert("user::proc::disable");
    dispatcher_concerned_types.insert("user::file::enable");
    dispatcher_concerned_types.insert("user::file::disable");
    dispatcher_concerned_types.insert("user::file::set");
    dispatcher_concerned_types.insert("user::net::enable");
    dispatcher_concerned_types.insert("user::net::disable");
    dispatcher_concerned_types.insert("user::net::insert");
    dispatcher_concerned_types.insert("user::net::delete");
}

static bool DispatcherFilter(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (!doc.is_object())
        return true;
    if (!doc["type"].is_string())
        return true;
    if (!dispatcher_concerned_types.contains(doc["type"]))
        return true;
    return false;
}

int DispatcherWait() {
    ThreadNameUpdate("dispatcher");
    DispatcherFilterInit();

    dispatcher = std::make_shared<Receiver>();

    dispatcher->AddHandler(DispatcherFilter);
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
    DBG("dispatcher enter");
    dispatcher->ConsumeWait();
    DBG("dispatcher exit");
    return 0;
}

void DispatcherExit() {
    if (dispatcher)
        dispatcher->Exit();
}

}; // namespace hackernel
