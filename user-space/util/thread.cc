/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/thread.h"

namespace hackernel {

thread_manager &thread_manager::global() {
    static thread_manager instance;
    return instance;
}

void thread_manager::wait_thread_exit() {
    for (auto &&t : threads_)
        t.join();
}

void thread_manager::create_thread(std::function<void(void)> &&t) {
    threads_.emplace_back(t);
}

void create_thread(std::function<void(void)> &&t) {
    thread_manager::global().create_thread(std::move(t));
}

void wait_thread_exit() {
    thread_manager::global().wait_thread_exit();
}

} // namespace hackernel
