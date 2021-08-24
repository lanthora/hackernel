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
  void setBroadcaster(std::shared_ptr<Broadcaster> Broadcaster) {
    this->BindBroadcaster = Broadcaster;
  }
  void newMessage(std::string Message) {
    const std::lock_guard<std::mutex> Lock(MessageQueueMutex);
    MessageQueue.push(Message);
    Signal.notify_one();
  }

  void startToConsume() {
    bool FinalHandler;
    Running = true;
    while (Running) {
      std::string Message;
      waitAndPopMessage(Message);

      if (exitHandler(Message))
        break;

      for (const auto &Handler : Handlers)
        if (FinalHandler = Handler(Message))
          break;

      if (!FinalHandler)
        defaultHandler(Message);
    }
  }
  void addHandler(std::function<bool(const std::string &)> NewHandler) {
    Handlers.push_back(NewHandler);
  }

private:
  void waitAndPopMessage(std::string &Message) {
    std::unique_lock<std::mutex> Lock(MessageQueueMutex);
    while (MessageQueue.empty())
      Signal.wait(Lock);

    Message = MessageQueue.front();
    MessageQueue.pop();
  }

  bool exitHandler(const std::string &Message) {
    if (Message != ReceiverExit)
      return false;

    Running = false;
    return true;
  }

  bool defaultHandler(const std::string &Message) {
    std::cout << Message << std::endl;
    return true;
  }

private:
  std::shared_ptr<Broadcaster> BindBroadcaster;
  std::queue<std::string> MessageQueue;
  std::mutex MessageQueueMutex;
  std::condition_variable Signal;
  bool Running;
  std::list<std::function<bool(const std::string &)>> Handlers;
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

  void exitAllReceiver() {
    notify(ReceiverExit);
  }

private:
  std::list<std::weak_ptr<Receiver>> Receivers;
  std::mutex ReceiversMutex;
};