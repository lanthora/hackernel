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

private:
    int Load();
    int SetAutoSaveTimer();

private:
    int Report(const std::string &cmd);
    int TrustedCmdInsert(const std::string &cmd);
    bool TrustedCmdCheck(const std::string &cmd);

public:
    static Auditor &GetInstance();
    static bool WarnCmdCheck(double count, double sum);

private:
    Auditor();
    ~Auditor();
    LRUCache<std::string, uint64_t> cmd_counter_;
    uint64_t cmd_sum_;
    std::mutex sl_mutex_;
    std::unordered_set<std::string> trusted_cmd_;
    std::shared_mutex trusted_cmd_mutex_;
};

}; // namespace process

}; // namespace hackernel

#endif
