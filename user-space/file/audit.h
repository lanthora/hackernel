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
    int Save();
    int Init();

private:
    int InitDefender();
    int Load();
    int SetAutoSaveTimer();
    bool Handler(const std::string &msg);
    void MarkChanged();

public:
    static Auditor &GetInstance();

private:
    Auditor();
    ~Auditor();
    bool enabled_ = true;
    std::mutex sl_mutex_; // 锁配置文件
    std::shared_ptr<Receiver> receiver_ = nullptr;
    std::chrono::system_clock::time_point last_update_time_;
    std::shared_mutex perms_mutex_; // 锁map
    std::map<std::string, FilePerm> perms_;
};

}; // namespace file

}; // namespace hackernel

#endif
