/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/protector.h"
#include "hackernel/ipc.h"
#include "hackernel/json.h"
#include "hackernel/thread.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include <fstream>

namespace hackernel {

file_protector &file_protector::global() {
    static file_protector instance;
    return instance;
}

file_protector::file_protector() {}

file_protector::~file_protector() {}

int file_protector::start() {
    audience_ = std::make_shared<audience>();
    if (!audience_) {
        ERR("make audience failed");
        return -ENOMEM;
    }
    audience_->add_msg_handler([&](const std::string &msg) { return handle_file_proc_msg(msg); });
    broadcaster::global().add_audience(audience_);

    change_thread_name("file");
    audience_->start_consume_msg();

    return 0;
}

bool file_protector::handle_file_proc_msg(const std::string &msg) {
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
        const file_perm perm = data["perm"];

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

int start_file_protector() {
    file_protector::global().start();
    return 0;
}

} // namespace hackernel
