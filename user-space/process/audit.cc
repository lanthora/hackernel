/* SPDX-License-Identifier: GPL-2.0-only */
#include "process/audit.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/timer.h"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace hackernel {

using namespace process;

bool Auditor::WarnCmdCheck(double count, double sum) {
    return -1.0 * (1.0 / count) * log(count / sum) > 1.0;
}

bool Auditor::TrustedCmdCheck(const std::string &cmd) {
    std::shared_lock<std::shared_mutex> lock(trusted_cmd_mutex_);
    return trusted_cmd_.contains(cmd);
}

int Auditor::TrustedCmdInsert(const std::string &cmd) {
    std::unique_lock<std::shared_mutex> trusted_lock(trusted_cmd_mutex_);
    trusted_cmd_.insert(cmd);
    return 0;
}

ProcPerm Auditor::HandlerNewCmd(const std::string &cmd) {

    if (TrustedCmdCheck(cmd))
        return PROCESS_ACCEPT;

    uint64_t count = 0UL;
    cmd_counter_.Get(cmd, count);
    ++count;
    ++cmd_sum_;

    if (WarnCmdCheck(count, cmd_sum_)) {
        Report(cmd);
    } else {
        TrustedCmdInsert(cmd);
    }

    cmd_counter_.Put(cmd, count);

    return PROCESS_ACCEPT;
}

int Auditor::Report(const std::string &cmd) {
    nlohmann::json doc;
    doc["type"] = "audit::proc::report";
    doc["cmd"] = cmd.data();
    std::string msg = InternalJsonWrapper(doc);
    Broadcaster::GetInstance().Notify(msg);

    DBG("audit=[%s]", msg.data());
    return 0;
}

Auditor &Auditor::GetInstance() {
    static Auditor instance;
    return instance;
}

int Auditor::Load() {
    std::lock_guard<std::mutex> lock(sl_mutex_);

    std::ifstream input("/var/lib/hackernel/process.json");
    if (!input) {
        WARN("open /var/lib/hackernel/process.json failed.");
        return -EINVAL;
    }

    nlohmann::json doc;
    try {
        input >> doc;
    } catch (nlohmann::json::parse_error &ex) {
        WARN("parse error");
    }
    input.close();

    if (!doc.is_object()) {
        WARN("process.json is not json");
        return -EINVAL;
    }

    if (!doc["capacity"].is_number_unsigned()) {
        WARN("can not read capacity from capacity");
        return -EINVAL;
    }

    if (!doc["raw"].is_array()) {
        WARN("can not read raw from capacity");
        return -EINVAL;
    }

    if (!doc["trusted"].is_array()) {
        WARN("can not read trusted list from capacity");
        return -EINVAL;
    }

    cmd_sum_ = 0UL;

    LRUData<std::string, uint64_t> data;
    data.capacity = doc["capacity"];

    for (const auto &element : doc["raw"]) {
        if (!element["cmd"].is_string() || !element["count"].is_number_unsigned()) {
            WARN("raw element parse failed, element=[%s]", element.dump().data());
            continue;
        }
        data.raw.push_back(std::make_pair<std::string, uint64_t>(element["cmd"], element["count"]));
        cmd_sum_ += static_cast<uint64_t>(element["count"]);
    }

    for (const auto &trusted : doc["trusted"]) {
        if (!trusted.is_string()) {
            WARN("trusted item is not string, trusted=[%s]", trusted.dump().data());
            continue;
        }
        TrustedCmdInsert(trusted);
    }

    cmd_counter_.Import(data);
    return 0;
}

Auditor::Auditor() {
    const size_t CMD_COUNT_MAX = 1024;
    cmd_counter_.SetCapacity(CMD_COUNT_MAX);
    cmd_counter_.SetOnEarseHandler([&](const std::pair<std::string, uint64_t> &item) {
        cmd_sum_ -= item.second;
        return;
    });
    Load();
    SetAutoSaveTimer();
}

int Auditor::Save() {
    std::lock_guard<std::mutex> lock(sl_mutex_);

    static uint64_t last_cmd_sum = 0L;
    if (cmd_sum_ == last_cmd_sum)
        return 0;

    last_cmd_sum = cmd_sum_;

    std::error_code ec;
    std::filesystem::create_directories("/var/lib/hackernel", ec);
    if (ec) {
        WARN("create dir /var/lib/hackernel failed, errmsg=[%s]", ec.message().data());
        return -EPERM;
    }

    std::ofstream output("/var/lib/hackernel/process.json");
    if (!output) {
        WARN("open /var/lib/hackernel/process.json failed");
        return -EPERM;
    }

    LRUData<std::string, uint64_t> data;
    cmd_counter_.Export(data);

    nlohmann::json doc;
    doc["capacity"] = data.capacity;
    for (const auto &it : data.raw) {
        nlohmann::json raw;
        raw["cmd"] = it.first;
        raw["count"] = it.second;
        doc["raw"].push_back(raw);
    }

    std::unique_lock<std::shared_mutex> trusted_lock(trusted_cmd_mutex_);
    for (const auto &it : trusted_cmd_) {
        doc["trusted"].push_back(it);
    }

    output << std::setw(4) << doc;
    output.close();
    return 0;
}

int Auditor::SetAutoSaveTimer() {
    timer::Element element;
    element.time_point = std::chrono::system_clock::now() + std::chrono::minutes(1);
    element.func = [&]() {
        Save();
        SetAutoSaveTimer();
    };
    timer::Timer::GetInstance().Insert(element);
    return 0;
}

Auditor::~Auditor() {
    Save();
}

}; // namespace hackernel
