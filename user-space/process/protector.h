/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PROCESS_AUDIT_H
#define PROCESS_AUDIT_H

#include "hackernel/broadcaster.h"
#include "hackernel/lru.h"
#include "hackernel/process.h"
#include <chrono>
#include <set>
#include <shared_mutex>
#include <string>

namespace hackernel {

int start_process_protector();

struct process_cmd_ctx {
    std::string workdir;
    std::string binary;
    std::string argv;
};

struct process_cmd_ctx_cmp {
    bool operator()(const process_cmd_ctx &a, const process_cmd_ctx &b) const {
        if (a.workdir != b.workdir)
            return a.workdir < b.workdir;
        if (a.binary != b.binary)
            return a.binary < b.binary;
        if (a.argv != b.argv)
            return a.argv < b.argv;
        return false;
    }
};

class process_protector {

public:
    proc_perm handle_new_cmd(const process_cmd_ctx &cmd);
    int init();
    int start();

private:
    int report(const process_cmd_ctx &cmd);
    int insert_trusted_cmd(const process_cmd_ctx &cmd);
    int delete_trusted_cmd(const process_cmd_ctx &cmd);
    int clear_trusted_cmd();
    bool is_trusted(const process_cmd_ctx &cmd);
    bool handle_process_msg(const std::string &msg);

public:
    static process_protector &global();

private:
    std::set<process_cmd_ctx, process_cmd_ctx_cmp> trusted_;
    std::shared_mutex mutex_;
    proc_perm judge_ = PROCESS_ACCEPT;
    bool enabled_ = false;
    std::shared_ptr<audience> audience_ = nullptr;
};

}; // namespace hackernel

#endif
