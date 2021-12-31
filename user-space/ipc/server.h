#ifndef IPC_SERVER_H
#define IPC_SERVER_H

#include "hackernel/ipc.h"
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <sys/socket.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace hackernel {

class ConnCache {
    typedef std::list<std::pair<Session, UserConn>> lru_list;
    typedef std::unordered_map<Session, lru_list::iterator> lru_map;

private:
    lru_list lru_list_;
    lru_map lru_map_;
    size_t lru_capacity_ = 1;
    std::mutex lru_lock_;
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
    int MsgSub(const std::string &section, const UserConn &user);
    int MsgUnsub(const std::string &section, const UserConn &user);
    int SendMsgToSubscriber(const std::string &section, const std::string &msg);
    int TokenUpdate(const std::string &token);

private:
    IpcServer() {}
    std::shared_ptr<Receiver> receiver_ = nullptr;
    bool running_;
    int socket_;
    std::map<std::string, std::list<UserConn>> sub_;
    std::mutex sub_lock_;
    std::atomic<Session> id_ = SYSTEM_SESSION;
    std::string token_;

private:
    int UnixDomainSocketWait();
    Session NewUserSession();
};

}; // namespace hackernel

#endif
