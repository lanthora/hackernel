/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/timer.h"

namespace hackernel {

int start_timer() {
    update_thread_name("timer");
    DBG("timer enter");
    timer::timer::global().start();
    DBG("timer exit");
    return 0;
}

void stop_timer() {
    timer::timer::global().stop();
    return;
}

namespace timer {

int timer::insert(const event &e) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(e);
    }
    cv_.notify_one();
    return 0;
}

int timer::start() {
    event e;
    running_ = current_service_status();
    while (running_) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [&]() { return !queue_.empty() || !running_; });
            if (!running_)
                break;

            if (std::chrono::system_clock::now() < queue_.top().time_point) {
                cv_.wait_until(lock, queue_.top().time_point);
                continue;
            }

            e = queue_.top();
            queue_.pop();
        }
        e.func();
    }
    return 0;
}

int timer::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
    }
    cv_.notify_one();
    return 0;
}

timer &timer::global() {
    static timer instance;
    return instance;
}

}; // namespace timer

}; // namespace hackernel
