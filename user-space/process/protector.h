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

int start_process_protector();

class process_protector {

public:
    ProcPerm handle_new_cmd(const std::string &cmd);
    int init();
    int start();

private:
    int report(const std::string &cmd);
    int insert_trusted_cmd(const std::string &cmd);
    int delete_trusted_cmd(const std::string &cmd);
    int clear_trusted_cmd();
    bool is_trusted(const std::string &cmd);
    bool handle_proc_msg(const std::string &msg);

public:
    static process_protector &global();

private:
    process_protector();
    ~process_protector();
    std::unordered_set<std::string> trusted_;
    std::shared_mutex mutex_;
    ProcPerm judge_ = PROCESS_ACCEPT;
    bool enabled_ = false;
    std::shared_ptr<audience> audience_ = nullptr;
};

}; // namespace hackernel

#endif
