#ifndef HACKERNEL_BROADCASTER_H
#define HACKERNEL_BROADCASTER_H

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
    void SetBroadcaster(std::shared_ptr<Broadcaster> broadcaster);
    void NewMessage(std::string message);
    void StartToConsume();
    void AddHandler(std::function<bool(const std::string&)> new_handler);

private:
    void WaitAndPopMessage(std::string& message);
    bool ExitHandler(const std::string& message);
    bool DefaultHandler(const std::string& message);

private:
    std::shared_ptr<Broadcaster> bind_broadcaster_;
    std::queue<std::string> message_queue_;
    std::mutex message_queue_mutex_;
    std::condition_variable signal_;
    bool running_;
    std::list<std::function<bool(const std::string&)>> handlers_;
};

class Broadcaster : public std::enable_shared_from_this<Broadcaster> {
public:
    void AddReceiver(std::shared_ptr<Receiver> receiver);
    void Notify(std::string message);
    void ExitAllReceiver();

private:
    std::list<std::weak_ptr<Receiver>> receivers_;
    std::mutex receivers_mutex_;
};

#endif
