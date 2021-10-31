#include "broadcaster.h"

void Receiver::SetBroadcaster(std::shared_ptr<Broadcaster> broadcaster) {
    this->bind_broadcaster_ = broadcaster;
}

void Receiver::NewMessage(std::string message) {
    const std::lock_guard<std::mutex> lock(message_queue_mutex_);
    message_queue_.push(message);
    signal_.notify_one();
}

void Receiver::StartToConsume() {
    bool final_handler;
    running_ = true;
    while (running_) {
        std::string message;
        WaitAndPopMessage(message);

        if (ExitHandler(message))
            break;

        for (const auto& handler : handlers_)
            if (final_handler = handler(message))
                break;

        if (!final_handler)
            DefaultHandler(message);
    }
}

void Receiver::AddHandler(std::function<bool(const std::string&)> new_handler) {
    handlers_.push_back(new_handler);
}

void Receiver::WaitAndPopMessage(std::string& message) {
    std::unique_lock<std::mutex> lock(message_queue_mutex_);
    while (message_queue_.empty())
        signal_.wait(lock);

    message = message_queue_.front();
    message_queue_.pop();
}

bool Receiver::ExitHandler(const std::string& message) {
    if (message != ReceiverExit)
        return false;

    running_ = false;
    return true;
}

bool Receiver::DefaultHandler(const std::string& message) {
    std::cout << message << std::endl;
    return true;
}

void Broadcaster::AddReceiver(std::shared_ptr<Receiver> receiver) {
    receiver->SetBroadcaster(shared_from_this());
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    receivers_.push_back(receiver);
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
    Notify(ReceiverExit);
}
