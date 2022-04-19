/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/threads.h"

namespace hackernel {

Threads &Threads::GetInstance() {
    static Threads instance;
    return instance;
}

// FIXME: 当主线程已经开始等待退出后,某个子线程调用AddThread会造成无限等待
void Threads::WaitAllThreadsExit() {
    for (auto &&t : threads_)
        t.join();
}

void Threads::AddThread(std::function<void(void)> &&t) {
    threads_.emplace_back(t);
}

} // namespace hackernel
