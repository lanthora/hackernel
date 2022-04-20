/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/timer.h"

namespace hackernel {
namespace timer {

int Timer::Insert(const Element &element) {
    queue_mutex_.lock();
    queue_.push(element);
    queue_mutex_.unlock();

    cv_.notify_one();
    return 0;
}

int Timer::RunWait() {
    running_ = RUNNING();
    while (running_) {
        std::unique_lock<std::mutex> lock(sync_mutex_);
        cv_.wait(lock, [&]() { return !queue_.empty() || !running_; });
        if (!running_)
            break;

        if (std::chrono::system_clock::now() < queue_.top().time_point) {
            cv_.wait_until(lock, queue_.top().time_point);
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
    sync_mutex_.lock();
    running_ = false;
    sync_mutex_.unlock();

    cv_.notify_one();
    return 0;
}

Timer &Timer::GetInstance() {
    static Timer instance;
    return instance;
}

}; // namespace timer

int TimerWait() {
    ThreadNameUpdate("timer");
    DBG("timer enter");
    timer::Timer::GetInstance().RunWait();
    DBG("timer exit");
    return 0;
}

void TimerExit() {
    timer::Timer::GetInstance().Exit();
    return;
}

}; // namespace hackernel
