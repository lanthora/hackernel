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
    LRUCache<std::string, uint64_t> cmd_count_;
    uint64_t cmd_count_sum_ = 0UL;
};

}; // namespace process

}; // namespace hackernel

#endif
