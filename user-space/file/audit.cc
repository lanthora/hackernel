#include "file/audit.h"

namespace hackernel {

namespace file {

Auditor &Auditor::GetInstance() {
    static Auditor instance;
    return instance;
}

Auditor::Auditor() {
    Load();
    SetAutoSaveTimer();
}

Auditor::~Auditor() {
    Save();
}

int Auditor::Save() {
    return 0;
}

int Auditor::Init() {
    return 0;
}

int Auditor::Load() {
    return 0;
}

int Auditor::SetAutoSaveTimer() {
    return 0;
}

} // namespace file

} // namespace hackernel
