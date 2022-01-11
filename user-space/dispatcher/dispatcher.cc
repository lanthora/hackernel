/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/dispatcher.h"
#include "dispatcher/handler.h"
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <unordered_set>

namespace hackernel {

static std::shared_ptr<Receiver> dispatcher = nullptr;
static std::unordered_set<std::string> enabled_type_set;

static void DispatcherFilterInit() {
    enabled_type_set.clear();
    enabled_type_set.insert("user::proc::enable");
    enabled_type_set.insert("user::proc::disable");
    enabled_type_set.insert("user::file::enable");
    enabled_type_set.insert("user::file::disable");
    enabled_type_set.insert("user::file::set");
    enabled_type_set.insert("user::net::enable");
    enabled_type_set.insert("user::net::disable");
    enabled_type_set.insert("user::net::insert");
    enabled_type_set.insert("user::net::delete");
}

static bool DispatcherFilter(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (!doc.is_object())
        return true;
    if (!doc["type"].is_string())
        return true;
    if (!enabled_type_set.contains(doc["type"]))
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
