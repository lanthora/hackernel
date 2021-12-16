#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "broadcaster.h"
#include "hackernel/util.h"
#include <list>
#include <memory>
#include <string>
#include <sys/un.h>
#include <unordered_map>

namespace hackernel {

typedef int32_t session_t;
typedef std::shared_ptr<struct sockaddr_un> conn_t;

class SessionCache {
    typedef std::list<std::pair<session_t, conn_t>> lru_list;
    typedef std::unordered_map<session_t, lru_list::iterator> lru_map;

private:
    lru_list lru_list_;
    lru_map lru_map_;
    size_t lru_capacity_ = 1;
    SessionCache();

public:
    static SessionCache &GetInstance();
    int Get(session_t key, conn_t &val);
    int Put(session_t key, conn_t value);
    int SetCapacity(size_t capacity);
    static size_t GenSessionID();
};

class IpcServer {
public:
    static IpcServer &GetInstance();
    int Init();
    int StartWait();
    int Stop();
    int SendMsgToClient(session_t id, const std::string &msg);

private:
    IpcServer() {}
    std::shared_ptr<Receiver> receiver_ = nullptr;
    bool running_;
    int server_sock;

private:
    int UnixDomainSocketWait();
};

int IpcWait();
void IpcExit();

}; // namespace hackernel

#endif
