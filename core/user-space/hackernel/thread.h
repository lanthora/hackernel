/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_THREADS_H
#define HACKERNEL_THREADS_H

#include <functional>
#include <list>
#include <thread>

namespace hackernel {

class thread_manager {

public:
    void wait_thread_exit();
    void create_thread(std::function<void(void)> &&t);

public:
    static thread_manager &global();

private:
    std::list<std::thread> threads_;
};

void wait_thread_exit();
void create_thread(std::function<void(void)> &&t);

} // namespace hackernel

#endif
