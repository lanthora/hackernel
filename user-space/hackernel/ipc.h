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

typedef int32_t Session;
typedef std::shared_ptr<struct sockaddr> UserID;
typedef int UserIDSize;
typedef std::pair<UserID, UserIDSize> UserConn;

class ConnCache {
    typedef std::list<std::pair<Session, UserConn>> lru_list;
    typedef std::unordered_map<Session, lru_list::iterator> lru_map;

private:
    lru_list lru_list_;
    lru_map lru_map_;
    size_t lru_capacity_ = 1;
    ConnCache();

public:
    static ConnCache &GetInstance();
    int Get(const Session &key, UserConn &value);
    int Put(const Session &key, const UserConn &value);
    int SetCapacity(size_t capacity);
};

class IpcServer {
public:
    static IpcServer &GetInstance();
    int Init();
    int StartWait();
    int Stop();
    int SendMsgToClient(Session id, const std::string &msg);

private:
    IpcServer() {}
    std::shared_ptr<Receiver> receiver_ = nullptr;
    bool running_;
    int socket_;
    std::atomic<Session> id_ = 0;

private:
    int UnixDomainSocketWait();
};

int IpcWait();
void IpcExit();

}; // namespace hackernel

#endif
