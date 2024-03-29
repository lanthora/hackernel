/* SPDX-License-Identifier: GPL-2.0-only */
#include "process/protector.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/thread.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include "ipc/server.h"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace hackernel {

bool operator==(const process_cmd_ctx &a, const process_cmd_ctx &b) {
    return a.workdir == b.workdir && a.binary == b.binary && a.argv == b.argv;
}

bool process_protector::is_trusted(const process_cmd_ctx &cmd) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return trusted_.contains(cmd);
}

int process_protector::insert_trusted_cmd(const process_cmd_ctx &cmd) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    DBG("trusted insert, workdir=[%s] binary=[%s] argv=[%s]", cmd.workdir.data(), cmd.binary.data(), cmd.argv.data());
    trusted_.insert(cmd);
    return 0;
}

int process_protector::delete_trusted_cmd(const process_cmd_ctx &cmd) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    DBG("trusted delete, workdir=[%s] binary=[%s] argv=[%s]", cmd.workdir.data(), cmd.binary.data(), cmd.argv.data());
    trusted_.erase(cmd);
    return 0;
}

int process_protector::clear_trusted_cmd() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    DBG("trusted clear");
    trusted_.clear();
    return 0;
}

proc_perm process_protector::handle_new_cmd(const process_cmd_ctx &cmd) {
    if (judge_ != PROCESS_ACCEPT && judge_ != PROCESS_REJECT)
        return PROCESS_ACCEPT;

    if (is_trusted(cmd))
        return PROCESS_ACCEPT;

    report(cmd);
    return judge_;
}

int process_protector::report(const process_cmd_ctx &cmd) {
    nlohmann::json doc;
    doc["type"] = "audit::proc::report";
    doc["workdir"] = cmd.workdir;
    doc["binary"] = cmd.binary;
    doc["argv"] = cmd.argv;
    doc["judge"] = judge_;
    std::string msg = generate_system_broadcast_msg(doc);
    broadcaster::global().broadcast(msg);

    DBG("audit=[%s]", msg.data());
    return 0;
}

process_protector &process_protector::global() {
    static process_protector instance;
    return instance;
}

// 根据广播中的消息更新配置,消息产生与配置更新解耦
bool process_protector::handle_process_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (!doc["type"].is_string())
        return false;
    const std::string &type = doc["type"];

    if (type == "user::proc::trusted::insert") {
        nlohmann::json &data = doc["data"];
        if (!data["workdir"].is_string())
            return false;
        if (!data["binary"].is_string())
            return false;
        if (!data["argv"].is_string())
            return false;
        process_cmd_ctx cmd;
        cmd.workdir = data["workdir"];
        cmd.binary = data["binary"];
        cmd.argv = data["argv"];
        data["code"] = insert_trusted_cmd(cmd);
        ipc::ipc_server::global().send_msg_to_client(doc);
        return true;
    }

    if (type == "user::proc::trusted::delete") {
        nlohmann::json &data = doc["data"];
        if (!data["workdir"].is_string())
            return false;
        if (!data["binary"].is_string())
            return false;
        if (!data["argv"].is_string())
            return false;
        process_cmd_ctx cmd;
        cmd.workdir = data["workdir"];
        cmd.binary = data["binary"];
        cmd.argv = data["argv"];
        data["code"] = delete_trusted_cmd(cmd);
        ipc::ipc_server::global().send_msg_to_client(doc);
        return true;
    }

    if (type == "user::proc::trusted::clear") {
        nlohmann::json &data = doc["data"];
        data["code"] = clear_trusted_cmd();
        ipc::ipc_server::global().send_msg_to_client(doc);
        return true;
    }

    if (type == "user::proc::judge") {
        nlohmann::json &data = doc["data"];
        if (!data["judge"].is_number_integer())
            return false;
        judge_ = data["judge"];
        data["code"] = 0;
        ipc::ipc_server::global().send_msg_to_client(doc);
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

int process_protector::init() {
    audience_ = std::make_shared<audience>();
    if (!audience_) {
        ERR("make audience failed");
        return -ENOMEM;
    }

    audience_->add_message_handler([&](const std::string &msg) { return handle_process_msg(msg); });
    broadcaster::global().add_audience(audience_);
    return 0;
}

int process_protector::start() {
    update_thread_name("process");
    audience_->start_consuming_message();
    return 0;
}

int start_process_protector() {
    process_protector::global().init();
    process_protector::global().start();
    return 0;
}

}; // namespace hackernel
