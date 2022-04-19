/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FILE_AUDIT_H
#define FILE_AUDIT_H

#include "hackernel/broadcaster.h"
#include "hackernel/file.h"
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>

namespace hackernel {

namespace file {

class Auditor {

public:
    int Init();

private:
    bool Handler(const std::string &msg);

public:
    static Auditor &GetInstance();

private:
    Auditor();
    ~Auditor();
    bool enabled_ = false;
    std::shared_ptr<Receiver> receiver_ = nullptr;
    std::shared_mutex mutex_;
    std::map<std::string, FilePerm> perms_;
};

}; // namespace file

}; // namespace hackernel

#endif
