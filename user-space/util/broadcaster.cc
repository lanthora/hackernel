#include "hackernel/broadcaster.h"

void Receiver::SetBroadcaster(std::shared_ptr<Broadcaster> broadcaster) {
    this->bind_broadcaster_ = broadcaster;
}

void Receiver::NewMessage(std::string message) {
    const std::lock_guard<std::mutex> lock(message_queue_mutex_);
    message_queue_.push(message);
    signal_.notify_one();
}

void Receiver::StartToConsume() {
    std::string message;

    running_ = true;
    while (running_) {
        if (WaitAndPopMessage(message))
            continue;

        for (const auto& handler : handlers_)
            handler(message);
    }
}

void Receiver::Stop() {
    running_ = false;
}

void Receiver::AddHandler(std::function<bool(const std::string&)> new_handler) {
    handlers_.push_back(new_handler);
}

int Receiver::WaitAndPopMessage(std::string& message) {
    using namespace std::chrono_literals;

    std::unique_lock<std::mutex> lock(message_queue_mutex_);
    while (message_queue_.empty()) {
        signal_.wait_for(lock, 100ms);
        if (!running_)
            return -1;
    }

    message = message_queue_.front();
    message_queue_.pop();
    return 0;
}

Broadcaster& Broadcaster::GetInstance() {
    static Broadcaster instance;
    return instance;
}

void Broadcaster::AddReceiver(std::shared_ptr<Receiver> receiver) {
    receiver->SetBroadcaster(shared_from_this());
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    receivers_.push_back(receiver);
}

void Broadcaster::DelReceiver(std::shared_ptr<Receiver> receiver){
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    receivers_.remove(receiver);
}


void Broadcaster::Notify(std::string message) {
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    for (auto& receiver : receivers_) {
        auto recv = receiver.lock();
        if (!recv) {
            continue;
        }
        recv->NewMessage(message);
    }
}

void Broadcaster::ExitAllReceiver() {
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    for (auto& receiver : receivers_) {
        auto recv = receiver.lock();
        if (!recv) {
            continue;
        }
        recv->Stop();
    }
    receivers_.clear();
}
