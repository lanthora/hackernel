#ifndef HACKERNEL_THREADS_H
#define HACKERNEL_THREADS_H

#include <functional>
#include <thread>
#include <vector>

namespace hackernel {

class Threads {

public:
    void WaitAllThreadsExit();
    void AddThread(std::function<void(void)> &&t);

public:
    static Threads &GetInstance();

private:
    Threads() {}
    std::vector<std::thread> threads_;
};

} // namespace hackernel

#endif
