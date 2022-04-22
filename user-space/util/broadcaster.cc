/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/broadcaster.h"
#include "hackernel/util.h"

namespace hackernel {

int stop_all_audience() {
    broadcaster::global().notify_audience_stop();
    return 0;
}

void audience::set_broadcaster(std::weak_ptr<broadcaster> broadcaster) {
    this->bind_broadcaster_ = broadcaster;
}

void audience::save_message(std::string message) {
    if (!running_)
        return;

    mutex_.lock();
    message_queue_.push(message);
    mutex_.unlock();

    cv_.notify_one();
}

void audience::start_consume_msg() {
    std::string message;

    running_ = get_running_status();
    while (running_) {
        if (wait_message(message))
            continue;

        for (const auto &handler : handlers_) {
            if (handler(message)) {
                break;
            }
        }
    }
}

void audience::stop_consume_msg() {
    mutex_.lock();
    running_ = false;
    mutex_.unlock();

    cv_.notify_one();
}

void audience::add_msg_handler(std::function<bool(const std::string &)> new_handler) {
    handlers_.push_back([=](const std::string &msg) -> bool {
        try {
            return new_handler(msg);
        } catch (std::exception &ex) {
            ERR("handler error, request msg=[%s]", msg.data());
            stop_server(HACKERNEL_BAD_AUDIENCE);
            return false;
        }
    });
}

int audience::wait_message(std::string &message) {
    using namespace std::chrono_literals;

    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [&] { return !running_ || !message_queue_.empty(); });

    if (!running_)
        return -EPERM;

    message = message_queue_.front();
    message_queue_.pop();
    return 0;
}

broadcaster &broadcaster::global() {
    static broadcaster instance;
    return instance;
}

void broadcaster::add_audience(std::shared_ptr<audience> audience) {
    audience->set_broadcaster(weak_from_this());
    const std::lock_guard<std::mutex> lock(mutex_);
    audience_.push_back(audience);
}

void broadcaster::del_audience(std::shared_ptr<audience> audience) {
    const std::lock_guard<std::mutex> lock(mutex_);
    audience_.remove(audience);
}

void broadcaster::broadcast(std::string message) {
    const std::lock_guard<std::mutex> lock(mutex_);
    for (auto &audience : audience_)
        audience->save_message(message);
}

void broadcaster::notify_audience_stop() {
    const std::lock_guard<std::mutex> lock(mutex_);
    for (auto &audience : audience_)
        audience->stop_consume_msg();
    audience_.clear();
}

}; // namespace hackernel
