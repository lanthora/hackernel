#ifndef PROCESS_AUDIT_H
#define PROCESS_AUDIT_H

#include "hackernel/process.h"
#include <string>

namespace hackernel {

namespace process {

class Auditor {

public:
    ProcPerm HandlerNewCmd(std::string msg);

private:
    int Report(std::string msg);

public:
    static Auditor &GetInstance();

private:
    Auditor() {}
};

}; // namespace process

}; // namespace hackernel

#endif
