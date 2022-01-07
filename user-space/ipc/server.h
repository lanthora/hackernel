/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IPC_SERVER_H
#define IPC_SERVER_H

#include "hackernel/ipc.h"
#include "hackernel/lru.h"
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <sys/socket.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace hackernel {

namespace ipc {

typedef LRUCache<Session, UserConn> ConnCache;

class IpcServer {
public:
    static IpcServer &GetInstance();
    static ConnCache &GetConnCache();
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

}; // namespace ipc

}; // namespace hackernel

#endif
