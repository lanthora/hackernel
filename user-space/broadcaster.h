#pragma once

#include <condition_variable>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <queue>

#define ReceiverExit "EXIT"

class Broadcaster;
class Receiver;

class Receiver {
 public:
  void SetBroadcaster(std::shared_ptr<Broadcaster> broadcaster) {
    this->bind_broadcaster_ = broadcaster;
  }
  void NewMessage(std::string message) {
    const std::lock_guard<std::mutex> lock(message_queue_mutex_);
    message_queue_.push(message);
    signal_.notify_one();
  }

  void StartToConsume() {
    bool final_handler;
    running_ = true;
    while (running_) {
      std::string message;
      WaitAndPopMessage(message);

      if (ExitHandler(message)) break;

      for (const auto &handler : handlers_)
        if (final_handler = handler(message)) break;

      if (!final_handler) DefaultHandler(message);
    }
  }
  void AddHandler(std::function<bool(const std::string &)> new_handler) {
    handlers_.push_back(new_handler);
  }

 private:
  void WaitAndPopMessage(std::string &message) {
    std::unique_lock<std::mutex> lock(message_queue_mutex_);
    while (message_queue_.empty()) signal_.wait(lock);

    message = message_queue_.front();
    message_queue_.pop();
  }

  bool ExitHandler(const std::string &message) {
    if (message != ReceiverExit) return false;

    running_ = false;
    return true;
  }

  bool DefaultHandler(const std::string &message) {
    std::cout << message << std::endl;
    return true;
  }

 private:
  std::shared_ptr<Broadcaster> bind_broadcaster_;
  std::queue<std::string> message_queue_;
  std::mutex message_queue_mutex_;
  std::condition_variable signal_;
  bool running_;
  std::list<std::function<bool(const std::string &)>> handlers_;
};

class Broadcaster : public std::enable_shared_from_this<Broadcaster> {
 public:
  void AddReceiver(std::shared_ptr<Receiver> receiver) {
    receiver->SetBroadcaster(shared_from_this());
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    receivers_.push_back(receiver);
  }

  void Notify(std::string message) {
    const std::lock_guard<std::mutex> lock(receivers_mutex_);
    for (auto &receiver : receivers_) {
      auto recv = receiver.lock();
      if (!recv) {
        continue;
      }
      recv->NewMessage(message);
    }
  }

  void ExitAllReceiver() { Notify(ReceiverExit); }

 private:
  std::list<std::weak_ptr<Receiver>> receivers_;
  std::mutex receivers_mutex_;
};