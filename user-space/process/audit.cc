/* SPDX-License-Identifier: GPL-2.0-only */
#include "process/audit.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/threads.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include "ipc/server.h"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace hackernel {

namespace process {

bool Auditor::IsTrusted(const std::string &cmd) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return trusted_.contains(cmd);
}

int Auditor::TrustedCmdInsert(const std::string &cmd) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    DBG("trusted insert, cmd=[%s]", cmd.data());
    trusted_.insert(cmd);
    return 0;
}

int Auditor::TrustedCmdDelete(const std::string &cmd) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    DBG("trusted delete, cmd=[%s]", cmd.data());
    trusted_.erase(cmd);
    return 0;
}

int Auditor::TrustedCmdClear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    DBG("trusted clear");
    trusted_.clear();
    return 0;
}

ProcPerm Auditor::HandleNewCmd(const std::string &cmd) {
    if (judge_ != PROCESS_ACCEPT && judge_ != PROCESS_REJECT)
        return PROCESS_ACCEPT;

    if (IsTrusted(cmd))
        return PROCESS_ACCEPT;

    Report(cmd);
    return judge_;
}

int Auditor::Report(const std::string &cmd) {
    nlohmann::json doc;
    doc["type"] = "audit::proc::report";
    doc["cmd"] = cmd.data();
    doc["judge"] = judge_;
    std::string msg = InternalJsonWrapper(doc);
    Broadcaster::GetInstance().Notify(msg);

    DBG("audit=[%s]", msg.data());
    return 0;
}

Auditor &Auditor::GetInstance() {
    static Auditor instance;
    return instance;
}

Auditor::Auditor() {}

// 根据广播中的消息更新配置,消息产生与配置更新解耦
bool Auditor::Handler(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (!doc["type"].is_string())
        return false;
    const std::string &type = doc["type"];

    if (type == "user::proc::trusted::insert") {
        nlohmann::json &data = doc["data"];
        if (!data["cmd"].is_string())
            return false;
        std::string cmd = data["cmd"];
        data["code"] = TrustedCmdInsert(cmd);
        ipc::IpcServer::GetInstance().SendMsgToClient(doc);
        return true;
    }

    if (type == "user::proc::trusted::delete") {
        nlohmann::json &data = doc["data"];
        if (!data["cmd"].is_string())
            return false;
        std::string cmd = data["cmd"];
        data["code"] = TrustedCmdDelete(cmd);
        ipc::IpcServer::GetInstance().SendMsgToClient(doc);
        return true;
    }

    if (type == "user::proc::trusted::clear") {
        nlohmann::json &data = doc["data"];
        data["code"] = TrustedCmdClear();
        ipc::IpcServer::GetInstance().SendMsgToClient(doc);
        return true;
    }

    if (type == "user::proc::judge") {
        nlohmann::json &data = doc["data"];
        if (!data["judge"].is_number_integer())
            return false;
        judge_ = data["judge"];
        data["code"] = 0;
        ipc::IpcServer::GetInstance().SendMsgToClient(doc);
        return true;
    }

    if (type == "user::proc::enable") {
        enabled_ = true;
        return true;
    }

    if (type == "user::proc::disable") {
        enabled_ = false;
        return true;
    }

    return false;
}

int Auditor::Init() {
    receiver_ = std::make_shared<Receiver>();
    if (!receiver_) {
        ERR("make receiver failed");
        return -ENOMEM;
    }

    receiver_->AddHandler([&](const std::string &msg) { return Handler(msg); });
    Broadcaster::GetInstance().AddReceiver(receiver_);
    Threads::GetInstance().AddThread([&]() {
        ThreadNameUpdate("process");
        receiver_->ConsumeWait();
    });

    return 0;
}

Auditor::~Auditor() {}

} // namespace process

}; // namespace hackernel
