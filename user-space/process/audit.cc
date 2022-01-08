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

static bool CmdWarnCheck(double count, double sum) {
    return -1.0 * (1.0 / count) * log(count / sum) > 1.0;
}

ProcPerm Auditor::HandlerNewCmd(std::string cmd) {
    uint64_t count = 0UL;
    cmd_counter_.Get(cmd, count);
    ++count;
    ++cmd_sum_;
    if (CmdWarnCheck(count, cmd_sum_))
        Report(cmd);

    cmd_counter_.Put(cmd, count);

    return PROCESS_ACCEPT;
}

static int StringSplit(std::string text, const std::string &delimiter, std::vector<std::string> &output) {
    size_t pos = 0;
    output.clear();
    while ((pos = text.find(delimiter)) != std::string::npos) {
        output.push_back(text.substr(0, pos));
        text.erase(0, pos + delimiter.length());
    }
    if (text.size()) {
        output.push_back(text);
    }
    return 0;
}

int Auditor::Report(std::string cmd) {
    std::vector<std::string> detail;
    StringSplit(cmd, "\37", detail);
    if (detail.size() < 3) {
        ERR("invalid cmd, cmd=[%s]", cmd.data());
        return -EINVAL;
    }

    std::string workdir = detail[0];
    std::string path = detail[1];
    std::string argv = detail[2];

    for (size_t i = 3; i < detail.size(); ++i) {
        argv.append(" " + detail[i]);
    }

    nlohmann::json doc;
    doc["type"] = "audit::proc::report";
    doc["workdir"] = workdir;
    doc["path"] = path;
    doc["argv"] = argv;
    std::string msg = InternalJsonWrapper(doc);
    Broadcaster::GetInstance().Notify(msg);

    LOG("audit=[%s]", msg.data());
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
        ERR("parse error");
    }
    input.close();

    if (!doc.is_object() || !doc["capacity"].is_number_unsigned() || !doc["raw"].is_array()) {
        ERR("invalid process.json");
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

    std::error_code ec;
    std::filesystem::create_directories("/var/lib/hackernel", ec);
    if (ec) {
        ERR("create dir /var/lib/hackernel failed, errmsg=[%s]", ec.message().data());
        return -EPERM;
    }

    std::ofstream output("/var/lib/hackernel/process.json");
    if (!output) {
        ERR("open /var/lib/hackernel/process.json failed");
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
