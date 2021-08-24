#pragma once
#include <condition_variable>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <queue>

class Broadcaster;

class Receiver {
public:
  void setBroadcaster(std::shared_ptr<Broadcaster> Broadcaster) {
    this->BindBroadcaster = Broadcaster;
  }
  void newMessage(std::string Message) {
    const std::lock_guard<std::mutex> Lock(MessageQueueMutex);
    MessageQueue.push(Message);
    Signal.notify_one();
  }

  void startToConsume() {
    while (true) {
      std::string Message;
      waitAndPopMessage(Message);
      std::cout << Message << std::endl;
      if (Message == "exit") {
        break;
      }
    }
  }

private:
  void waitAndPopMessage(std::string &Message) {
    std::unique_lock<std::mutex> Lock(MessageQueueMutex);
    while (MessageQueue.empty()) {
      Signal.wait(Lock);
    }
    Message = MessageQueue.front();
    MessageQueue.pop();
  }

private:
  std::shared_ptr<Broadcaster> BindBroadcaster;
  std::queue<std::string> MessageQueue;
  std::mutex MessageQueueMutex;
  std::condition_variable Signal;
};

class Broadcaster : public std::enable_shared_from_this<Broadcaster> {
public:
  void addReceiver(std::shared_ptr<Receiver> Receiver) {
    Receiver->setBroadcaster(shared_from_this());
    const std::lock_guard<std::mutex> Lock(ReceiversMutex);
    Receivers.push_back(Receiver);
  }

  void notify(std::string Message) {
    const std::lock_guard<std::mutex> Lock(ReceiversMutex);
    for (auto &Receiver : Receivers) {
      auto Recv = Receiver.lock();
      if (!Recv) {
        continue;
      }
      Recv->newMessage(Message);
    }
  }

private:
  std::list<std::weak_ptr<Receiver>> Receivers;
  std::mutex ReceiversMutex;
};