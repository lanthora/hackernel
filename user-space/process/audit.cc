/* SPDX-License-Identifier: GPL-2.0-only */
#include "process/audit.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include <cmath>
#include <nlohmann/json.hpp>

namespace hackernel {

using namespace process;

static bool CmdWarnCheck(double count, double sum) {
    return -1.0 * (1.0 / count) * log(count / sum) > 1.0;
}

ProcPerm Auditor::HandlerNewCmd(std::string cmd) {
    uint64_t count = 0UL;
    cmd_count_.Get(cmd, count);
    ++count;
    ++cmd_count_sum_;
    if (CmdWarnCheck(count, cmd_count_sum_))
        Report(cmd);

    cmd_count_.Put(cmd, count);

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

Auditor::Auditor() {
    const size_t CMD_COUNT_MAX = 1024;
    cmd_count_.SetCapacity(CMD_COUNT_MAX);
    cmd_count_.SetOnEarseHandler([&](const std::pair<std::string, uint64_t> &item) {
        cmd_count_sum_ -= item.second;
        return;
    });
}

}; // namespace hackernel
