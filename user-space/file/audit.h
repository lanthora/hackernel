/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FILE_AUDIT_H
#define FILE_AUDIT_H

namespace hackernel {

namespace file {

class Auditor {

public:
    int Save();
    int Init();

private:
    int Load();
    int SetAutoSaveTimer();

public:
    static Auditor &GetInstance();

private:
    Auditor();
    ~Auditor();
    bool enabled_ = true;
};

}; // namespace file

}; // namespace hackernel

#endif
