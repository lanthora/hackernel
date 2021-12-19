#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "broadcaster.h"
#include "hackernel/util.h"
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unordered_map>
#include <vector>

namespace hackernel {

typedef int32_t Session;
typedef std::shared_ptr<struct sockaddr_un> UserID;
typedef int UserIDSize;
typedef std::pair<UserID, UserIDSize> UserConn;

const Session SYSTEM_SESSION = 0;

static inline std::string UserJsonWrapper(const int32_t &session, const nlohmann::json &data) {
    nlohmann::json doc;
    doc["session"] = session;
    doc["type"] = data["type"];
    doc["data"] = data;
    return doc.dump();
}

static inline std::string InternalJsonWrapper(const nlohmann::json &data) {
    return UserJsonWrapper(SYSTEM_SESSION, data);
}

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
    int MsgSub(std::string section, const UserConn &user);
    int MsgUnsub(std::string section, const UserConn &user);
    int SendMsgToSubscriber(std::string section, const std::string &msg);

private:
    IpcServer() {}
    std::shared_ptr<Receiver> receiver_ = nullptr;
    bool running_;
    int socket_;
    std::map<std::string, std::list<UserConn>> sub_;
    std::mutex sub_lock_;
    std::atomic<Session> id_ = SYSTEM_SESSION;

private:
    int UnixDomainSocketWait();
    Session NewUserSession();
};

int IpcWait();
void IpcExit();

}; // namespace hackernel

#endif
