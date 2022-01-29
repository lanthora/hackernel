/* SPDX-License-Identifier: GPL-2.0-only */
#include "ipc/server.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "ipc/handler.h"
#include <algorithm>
#include <errno.h>
#include <functional>
#include <nlohmann/json.hpp>
#include <thread>
#include <unistd.h>

namespace hackernel {

using namespace ipc;

IpcServer &IpcServer::GetInstance() {
    static IpcServer instance;
    return instance;
}

ConnCache &IpcServer::GetConnCache() {
    static ConnCache cache;
    return cache;
}

int IpcServer::Init() {
    receiver_ = std::make_shared<Receiver>();

    receiver_->AddHandler(KernelProcReport);
    receiver_->AddHandler(AuditProcReport);
    receiver_->AddHandler(KernelFileReport);
    receiver_->AddHandler(KernelProcEnable);
    receiver_->AddHandler(KernelProcDisable);
    receiver_->AddHandler(KernelFileSet);
    receiver_->AddHandler(KernelFileEnable);
    receiver_->AddHandler(KernelFileDisable);
    receiver_->AddHandler(KernelNetInsert);
    receiver_->AddHandler(KernelNetDelete);
    receiver_->AddHandler(KernelNetEnable);
    receiver_->AddHandler(KernelNetDisable);
    receiver_->AddHandler(UserMsgSub);
    receiver_->AddHandler(UserMsgUnsub);
    receiver_->AddHandler(UserCtrlExit);
    receiver_->AddHandler(UserCtrlToken);

    Broadcaster::GetInstance().AddReceiver(receiver_);
    return 0;
}

int IpcServer::StartWait() {
    ThreadNameUpdate("ipc-wait");
    DBG("ipc-wait enter");
    std::thread receiver_thread([&]() {
        ThreadNameUpdate("ipc-recevier");
        DBG("ipc-recevier enter");
        receiver_->ConsumeWait();
        DBG("ipc-recevier exit");
    });
    std::thread socket_thread([&]() {
        ThreadNameUpdate("ipc-socket");
        DBG("ipc-socket enter");
        UnixDomainSocketWait();
        DBG("ipc-socket exit");
    });

    receiver_thread.join();
    socket_thread.join();
    DBG("ipc-wait exit");
    return 0;
}

int IpcServer::Stop() {
    running_ = false;

    if (socket_ && shutdown(socket_, SHUT_RDWR))
        DBG("close socket failed");

    if (receiver_)
        receiver_->Exit();
    return 0;
}

int IpcServer::SendMsgToClient(const nlohmann::json &doc) {
    UserConn conn;
    Session session = doc["session"];

    if (IpcServer::GetConnCache().Get(session, conn))
        return -ESRCH;

    nlohmann::json data = doc["data"];
    data["extra"] = conn.extra;

    return SendMsgToClient(conn, json::dump(data));
}

int IpcServer::SendMsgToClient(UserConn conn, const std::string &msg) {
    socklen_t len;
    struct sockaddr *peer;
    peer = (struct sockaddr *)conn.peer.get();
    len = conn.len;
    if (sendto(socket_, msg.data(), msg.size(), 0, peer, len) == -1) {
        WARN("send error, peer=[%s], msg=[%s]", ((struct sockaddr_un *)peer)->sun_path, msg.data());
        return -EPERM;
    }
    return 0;
}

int IpcServer::MsgSub(const std::string &section, const UserConn &user) {
    std::lock_guard<std::mutex> lock(sub_lock_);
    sub_[section].push_back(user);
    return 0;
}

int IpcServer::MsgUnsub(const std::string &section, const UserConn &user) {
    std::lock_guard<std::mutex> lock(sub_lock_);
    auto cmp = [&](const UserConn &item) { return strcmp(user.peer->sun_path, item.peer->sun_path) == 0; };
    auto it = std::find_if(sub_[section].begin(), sub_[section].end(), cmp);
    if (it == sub_[section].end())
        return -EPERM;
    sub_[section].erase(it);
    return 0;
}

int IpcServer::SendMsgToSubscriber(const nlohmann::json &doc) {
    std::string section = doc["type"];
    nlohmann::json data = doc["data"];
    return SendMsgToSubscriber(section, json::dump(data));
}

int IpcServer::SendMsgToSubscriber(const std::string &section, const std::string &msg) {
    struct sockaddr *peer;
    socklen_t len;
    std::lock_guard<std::mutex> lock(sub_lock_);

    for (auto it = sub_[section].begin(); it != sub_[section].end();) {
        peer = (struct sockaddr *)it->peer.get();
        len = it->len;

        if (sendto(socket_, msg.data(), msg.size(), 0, peer, len) == -1)
            it = sub_[section].erase(it);
        else
            ++it;
    }
    return 0;
}

int IpcServer::TokenUpdate(const std::string &token) {
    token_ = token;
    return 0;
}

int IpcServer::UnixDomainSocketWait() {
    const char *SOCK_PATH = "/tmp/hackernel.sock";
    const int BUFFER_SIZE = 1024;

    char buffer[BUFFER_SIZE];
    struct sockaddr_un server;

    socket_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (socket_ == -1) {
        ERR("unix domain socket create failed");
        goto errout;
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, SOCK_PATH);
    unlink(SOCK_PATH);
    if (bind(socket_, (struct sockaddr *)&server, sizeof(server)) == -1) {
        ERR("unix domain socket bind failed");
        goto errout;
    }

    socklen_t len;
    struct sockaddr_un peer;
    running_ = RUNNING();
    while (running_) {
        len = sizeof(peer);
        int size = recvfrom(socket_, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&peer, &len);

        if (size <= 0) {
            if (!size || errno == EAGAIN || errno == EINTR)
                continue;

            ERR("recvfrom errno=[%d] errmsg=[%s]", errno, strerror(errno));
            goto errout;
        }
        buffer[size] = 0;

        nlohmann::json data;
        try {
            data = json::parse(buffer);
        } catch (nlohmann::json::parse_error &ex) {
            WARN("parse error, buffer=[%s]", buffer);
            continue;
        }

        if (!data.is_object() || !data["type"].is_string()) {
            WARN("invalid request, buffer=[%s]", buffer);
            continue;
        }

        if (!token_.empty() && (!data["token"].is_string() || data["token"] != token_)) {
            WARN("invalid token, buffer=[%s]", buffer);
            continue;
        }

        UserConn conn;
        conn.peer = std::make_shared<struct sockaddr_un>(peer);
        conn.len = len;
        conn.extra = data["extra"];
        Session session = NewUserSession();
        IpcServer::GetConnCache().Put(session, conn);

        nlohmann::json doc;
        doc["session"] = session;
        doc["type"] = std::string(data["type"]);
        doc["data"] = data;
        Broadcaster::GetInstance().Notify(json::dump(doc));
    }

    close(socket_);
    return 0;

errout:
    close(socket_);
    SHUTDOWN(HACKERNEL_UNIX_DOMAIN_SOCKET);
    return -EPERM;
}

Session IpcServer::NewUserSession() {
    do {
        ++id_;
    } while (id_ == SYSTEM_SESSION);
    return id_;
}

int IpcWait() {
    IpcServer::GetInstance().Init();
    IpcServer::GetInstance().StartWait();
    return 0;
}

void IpcExit() {
    DBG("IpcExit Exit");
    IpcServer::GetInstance().Stop();
    return;
}

}; // namespace hackernel
