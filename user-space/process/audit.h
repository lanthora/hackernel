/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PROCESS_AUDIT_H
#define PROCESS_AUDIT_H

#include "hackernel/lru.h"
#include "hackernel/process.h"
#include <shared_mutex>
#include <string>
#include <unordered_set>

namespace hackernel {

namespace process {

class Auditor {

public:
    ProcPerm HandlerNewCmd(const std::string &cmd);
    int Save();
    int Init();

private:
    int Load();
    int SetAutoSaveTimer();

private:
    int Report(const std::string &cmd);
    int TrustedCmdInsert(const std::string &cmd);
    bool IsTrusted(const std::string &cmd);
    bool UpdateThenIsTrusted(const std::string &cmd);

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
};

}; // namespace process

}; // namespace hackernel

#endif
