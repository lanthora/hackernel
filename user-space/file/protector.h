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

class file_protector {

public:
    int start();

private:
    bool handle_file_proc_msg(const std::string &msg);

public:
    static file_protector &global();

private:
    file_protector();
    ~file_protector();
    bool enabled_ = false;
    std::shared_ptr<audience> audience_ = nullptr;
    std::shared_mutex mutex_;
    std::map<std::string, file_perm> perms_;
};

int start_file_protector();

}; // namespace hackernel

#endif
