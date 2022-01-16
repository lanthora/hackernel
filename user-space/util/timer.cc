/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/timer.h"

namespace hackernel {
namespace timer {

int Timer::Insert(const Element &element) {
    queue_mutex_.lock();
    queue_.push(element);
    queue_mutex_.unlock();

    signal_.notify_one();
    return 0;
}

int Timer::RunWait() {
    running_ = RUNNING();
    while (running_) {
        std::unique_lock<std::mutex> lock(sync_mutex_);
        if (queue_.empty()) {
            signal_.wait(lock);
            continue;
        }

        if (std::chrono::system_clock::now() < queue_.top().time_point) {
            signal_.wait_until(lock, queue_.top().time_point);
            continue;
        }

        queue_mutex_.lock();
        Element element = queue_.top();
        queue_.pop();
        queue_mutex_.unlock();

        element.func();
    }
    return 0;
}

int Timer::Exit() {
    running_ = false;
    signal_.notify_one();
    return 0;
}

Timer &Timer::GetInstance() {
    static Timer instance;
    return instance;
}

}; // namespace timer

int TimerWait() {
    ThreadNameUpdate("timer");
    LOG("timer enter");
    timer::Timer::GetInstance().RunWait();
    LOG("timer exit");
    return 0;
}

void TimerExit() {
    timer::Timer::GetInstance().Exit();
    return;
}

}; // namespace hackernel
