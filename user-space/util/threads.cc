#include "hackernel/threads.h"

namespace hackernel {

Threads &Threads::GetInstance() {
    static Threads instance;
    return instance;
}

void Threads::WaitAllThreadsExit() {
    for (auto &&t : threads_)
        t.join();
}

void Threads::AddThread(std::function<void(void)> &&t) {
    threads_.emplace_back(t);
}

} // namespace hackernel