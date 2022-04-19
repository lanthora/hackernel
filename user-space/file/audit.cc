/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/audit.h"
#include "hackernel/ipc.h"
#include "hackernel/json.h"
#include "hackernel/threads.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include <fstream>

namespace hackernel {

namespace file {

Auditor &Auditor::GetInstance() {
    static Auditor instance;
    return instance;
}

Auditor::Auditor() {}

Auditor::~Auditor() {}

int Auditor::Init() {
    receiver_ = std::make_shared<Receiver>();
    if (!receiver_) {
        ERR("make receiver failed");
        return -ENOMEM;
    }
    receiver_->AddHandler([&](const std::string &msg) { return Handler(msg); });
    Broadcaster::GetInstance().AddReceiver(receiver_);
    Threads::GetInstance().AddThread([&]() {
        ThreadNameUpdate("file");
        receiver_->ConsumeWait();
    });

    return 0;
}

bool Auditor::Handler(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (!doc["type"].is_string())
        return false;

    const std::string &type = doc["type"];
    if (type == "user::file::enable") {
        enabled_ = true;
        return true;
    }
    if (type == "user::file::disable") {
        enabled_ = false;
        std::unique_lock<std::shared_mutex> lock(mutex_);
        perms_.clear();
        return true;
    }
    if (type == "user::file::set") {
        nlohmann::json &data = doc["data"];
        if (!data["path"].is_string() || !data["perm"].is_number_unsigned())
            return false;
        const std::string path = data["path"];
        const FilePerm perm = data["perm"];

        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (perm) {
            perms_[path] = perm;
        } else {
            perms_.erase(path);
        }
        return true;
    }

    return false;
}

} // namespace file

} // namespace hackernel
