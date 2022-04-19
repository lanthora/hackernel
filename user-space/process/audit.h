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
    int Report(const std::string &cmd);
    int TrustedCmdInsert(const std::string &cmd);
    int TrustedCmdDelete(const std::string &cmd);
    bool IsTrusted(const std::string &cmd);
    bool Handler(const std::string &msg);

public:
    static Auditor &GetInstance();

private:
    Auditor();
    ~Auditor();
    std::unordered_set<std::string> trusted_;
    std::shared_mutex mutex_;
    ProcPerm judge_ = PROCESS_ACCEPT;
    bool enabled_ = false;
    std::shared_ptr<Receiver> receiver_ = nullptr;
};

}; // namespace process

}; // namespace hackernel

#endif
