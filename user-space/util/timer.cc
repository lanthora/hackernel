/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/timer.h"

namespace hackernel {

int start_timer() {
    change_thread_name("timer");
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

int timer::insert(const element &element) {
    queue_mutex_.lock();
    queue_.push(element);
    queue_mutex_.unlock();

    cv_.notify_one();
    return 0;
}

int timer::start() {
    running_ = get_running_status();
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
        element element = queue_.top();
        queue_.pop();
        queue_mutex_.unlock();

        element.func();
    }
    return 0;
}

int timer::stop() {
    sync_mutex_.lock();
    running_ = false;
    sync_mutex_.unlock();

    cv_.notify_one();
    return 0;
}

timer &timer::global() {
    static timer instance;
    return instance;
}

}; // namespace timer

}; // namespace hackernel
