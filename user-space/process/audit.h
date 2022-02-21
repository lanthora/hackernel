/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PROCESS_AUDIT_H
#define PROCESS_AUDIT_H

#include "hackernel/broadcaster.h"
#include "hackernel/lru.h"
#include "hackernel/process.h"
#include <chrono>
#include <shared_mutex>
#include <string>
#include <unordered_set>

namespace hackernel {

namespace process {

class Auditor {

public:
    ProcPerm HandleNewCmd(const std::string &cmd);
    int Init();

private:
    int Load();
    int Save();
    int SetAutoSaveTimer();

private:
    int Report(const std::string &cmd);
    int TrustedCmdInsert(const std::string &cmd);
    bool IsTrusted(const std::string &cmd);
    bool UpdateThenIsTrusted(const std::string &cmd);
    bool Handler(const std::string &msg);
    void MarkChanged();

public:
    static Auditor &GetInstance();

private:
    Auditor();
    ~Auditor();
    LRUCache<std::string, uint64_t> cmd_counter_;
    uint64_t sumcnt_;
    std::mutex sl_mutex_;
    std::unordered_set<std::string> trusted_cmd_;
    std::shared_mutex trusted_cmd_mutex_;
    std::string judge_ = "allow";
    bool enabled_ = true;
    std::shared_ptr<Receiver> receiver_ = nullptr;
    std::chrono::system_clock::time_point last_update_time_;
};

}; // namespace process

}; // namespace hackernel

#endif
