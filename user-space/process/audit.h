/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PROCESS_AUDIT_H
#define PROCESS_AUDIT_H

#include "hackernel/lru.h"
#include "hackernel/process.h"
#include <string>

namespace hackernel {

namespace process {

class Auditor {

public:
    ProcPerm HandlerNewCmd(std::string cmd);

private:
    int Report(std::string cmd);

public:
    static Auditor &GetInstance();

private:
    Auditor();
    ~Auditor();
    LRUCache<std::string, uint64_t> cmd_counter_;
    uint64_t cmd_sum_;
};

}; // namespace process

}; // namespace hackernel

#endif
