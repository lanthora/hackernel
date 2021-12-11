#ifndef HACKERNEL_COMMON_BROADCASTER_H
#define HACKERNEL_COMMON_BROADCASTER_H

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
    void SetBroadcaster(std::weak_ptr<Broadcaster> broadcaster);
    void NewMessage(std::string message);
    void ConsumeWait();
    void AddHandler(std::function<bool(const std::string&)> new_handler);
    void ExitNotify();

private:
    int PopMessageWait(std::string& message);

private:
    std::weak_ptr<Broadcaster> bind_broadcaster_;
    std::queue<std::string> message_queue_;
    std::mutex message_queue_mutex_;
    std::condition_variable signal_;
    bool running_;
    std::list<std::function<bool(const std::string&)>> handlers_;
};

class Broadcaster : public std::enable_shared_from_this<Broadcaster> {
public:
    static Broadcaster& GetInstance();
    void AddReceiver(std::shared_ptr<Receiver> receiver);
    void DelReceiver(std::shared_ptr<Receiver> receiver);
    void Notify(std::string message);
    void ExitAllReceiver();

private:
    Broadcaster() {}
    std::list<std::shared_ptr<Receiver>> receivers_;
    std::mutex receivers_mutex_;
};

#endif
