
#include "process/audit.h"

namespace hackernel {

using namespace process;

ProcPerm Auditor::HandlerNewCmd(std::string msg) {
    return PROCESS_ACCEPT;
}

int Auditor::Report(std::string msg) {
    return 0;
}

Auditor &Auditor::GetInstance() {
    static Auditor instance;
    return instance;
}

}; // namespace hackernel
