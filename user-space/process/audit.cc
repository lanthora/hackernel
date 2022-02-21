/* SPDX-License-Identifier: GPL-2.0-only */
#include "process/audit.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/threads.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace hackernel {

namespace process {

bool Auditor::UpdateThenIsTrusted(const std::string &cmd) {
    uint64_t curcnt = 0UL;
    cmd_counter_.Get(cmd, curcnt);
    ++curcnt;
    ++sumcnt_;

    auto trusted = -1.0 * (1.0 / curcnt) * log(1.0 * curcnt / sumcnt_) < 1.0;
    DBG("audit update, cmd=[%s] curcnt=[%ld] sumcnt_=[%ld] trusted=[%d]", cmd.data(), curcnt, sumcnt_, trusted);
    if (trusted)
        TrustedCmdInsert(cmd);
    cmd_counter_.Put(cmd, curcnt);

    MarkChanged();

    return trusted;
}

bool Auditor::IsTrusted(const std::string &cmd) {
    std::shared_lock<std::shared_mutex> lock(trusted_cmd_mutex_);
    return trusted_cmd_.contains(cmd);
}

int Auditor::TrustedCmdInsert(const std::string &cmd) {
    std::unique_lock<std::shared_mutex> trusted_lock(trusted_cmd_mutex_);
    DBG("audit trust, cmd=[%s]", cmd.data());
    trusted_cmd_.insert(cmd);
    return 0;
}

ProcPerm Auditor::HandleNewCmd(const std::string &cmd) {
    if (judge_ == "disable" || IsTrusted(cmd)) {
        return PROCESS_ACCEPT;
    }

    if (judge_ == "allow" && UpdateThenIsTrusted(cmd)) {
        return PROCESS_ACCEPT;
    }

    Report(cmd);

    return judge_ == "reject" ? PROCESS_REJECT : PROCESS_ACCEPT;
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
        WARN("can not read capacity from json");
        return -EINVAL;
    }

    if (!doc["raw"].is_array()) {
        WARN("can not read raw from json");
        return -EINVAL;
    }

    if (!doc["trusted"].is_array()) {
        WARN("can not read trusted list from json");
        return -EINVAL;
    }

    sumcnt_ = 0UL;

    LRUData<std::string, uint64_t> data;
    data.capacity = doc["capacity"];

    for (const auto &element : doc["raw"]) {
        if (!element["cmd"].is_string() || !element["count"].is_number_unsigned()) {
            WARN("raw element parse failed, element=[%s]", json::dump(element).data());
            continue;
        }
        data.raw.push_back(std::make_pair<std::string, uint64_t>(element["cmd"], element["count"]));
        sumcnt_ += static_cast<uint64_t>(element["count"]);
    }

    for (const auto &trusted : doc["trusted"]) {
        if (!trusted.is_string()) {
            WARN("trusted item is not string, trusted=[%s]", json::dump(trusted).data());
            continue;
        }
        TrustedCmdInsert(trusted);
    }

    cmd_counter_.Import(data);

    if (doc["enabled"].is_boolean()) {
        enabled_ = doc["enabled"];
    }

    if (doc["judge"].is_string()) {
        judge_ = doc["judge"];
    }

    return 0;
}

Auditor::Auditor() {}

// 根据广播中的消息更新配置,消息产生与配置更新解耦
bool Auditor::Handler(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] == "user::proc::enable") {
        enabled_ = true;
        MarkChanged();
        return true;
    }
    if (doc["type"] == "user::proc::disable") {
        enabled_ = false;
        MarkChanged();
        return true;
    }

    // TODO: 处理其他会引起进程配置变更的广播消息

    return false;
}

void Auditor::MarkChanged() {
    last_update_time_ = std::chrono::system_clock::now();
}

int Auditor::Init() {
    const size_t CMD_COUNT_MAX = 1024;
    cmd_counter_.SetCapacity(CMD_COUNT_MAX);
    cmd_counter_.SetOnEarseHandler([&](const std::pair<std::string, uint64_t> &item) {
        sumcnt_ -= item.second;
        return;
    });

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

    Load();
    SetAutoSaveTimer();

    if (enabled_) {
        ProcProtectEnable(SYSTEM_SESSION);
    }

    MarkChanged();
    return 0;
}

int Auditor::Save() {
    std::lock_guard<std::mutex> lock(sl_mutex_);

    static auto last_save_time = std::chrono::system_clock::now();

    if (last_save_time == last_update_time_)
        return 0;

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

    std::shared_lock<std::shared_mutex> trusted_lock(trusted_cmd_mutex_);
    for (const auto &it : trusted_cmd_) {
        doc["trusted"].push_back(it);
    }

    doc["enabled"] = enabled_;
    doc["judge"] = judge_;

    // TODO: 验证写入非UTF-8编码字符时是否出现异常
    output << std::setw(4) << doc;
    output.close();

    last_save_time = last_update_time_;
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

} // namespace process

}; // namespace hackernel
