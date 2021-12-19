#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include <errno.h>
#include <functional>
#include <nlohmann/json.hpp>
#include <thread>
#include <unistd.h>

namespace hackernel {

extern bool KernelProcReport(const std::string &msg);
extern bool KernelProcEnable(const std::string &msg);
extern bool KernelProcDisable(const std::string &msg);

extern bool KernelFileReport(const std::string &msg);
extern bool KernelFileSet(const std::string &msg);
extern bool KernelFileEnable(const std::string &msg);
extern bool KernelFileDisable(const std::string &msg);

extern bool KernelNetInsert(const std::string &msg);
extern bool KernelNetDelete(const std::string &msg);
extern bool KernelNetEnable(const std::string &msg);
extern bool KernelNetDisable(const std::string &msg);

IpcServer &IpcServer::GetInstance() {
    static IpcServer instance;
    return instance;
}

int IpcServer::Init() {
    receiver_ = std::make_shared<Receiver>();

    receiver_->AddHandler(KernelProcReport);
    receiver_->AddHandler(KernelProcEnable);
    receiver_->AddHandler(KernelProcDisable);
    receiver_->AddHandler(KernelFileReport);
    receiver_->AddHandler(KernelFileSet);
    receiver_->AddHandler(KernelFileEnable);
    receiver_->AddHandler(KernelFileDisable);
    receiver_->AddHandler(KernelNetInsert);
    receiver_->AddHandler(KernelNetDelete);
    receiver_->AddHandler(KernelNetEnable);
    receiver_->AddHandler(KernelNetDisable);

    Broadcaster::GetInstance().AddReceiver(receiver_);
    return 0;
}

int IpcServer::StartWait() {
    std::thread receiver_thread([&]() {
        ThreadNameUpdate("ipc-recevier");
        LOG("ipc-recevier enter");
        receiver_->ConsumeWait();
        LOG("ipc-recevier exit");
    });
    std::thread socket_thread([&]() {
        ThreadNameUpdate("ipc-socket");
        LOG("ipc-socket enter");
        UnixDomainSocketWait();
        LOG("ipc-socket exit");
    });

    receiver_thread.join();
    socket_thread.join();
    return 0;
}

int IpcServer::Stop() {
    running_ = false;
    if (receiver_)
        receiver_->Exit();
    return 0;
}

int IpcServer::SendMsgToClient(Session id, const std::string &msg) {
    UserConn conn;
    socklen_t len;
    struct sockaddr *peer;

    if (ConnCache::GetInstance().Get(id, conn))
        return -1;

    peer = (struct sockaddr *)conn.first.get();
    len = conn.second;
    sendto(socket_, msg.data(), msg.size(), 0, peer, len);
    return 0;
}

int IpcServer::UnixDomainSocketWait() {
    const char *SOCK_PATH = "/tmp/hackernel.sock";
    const struct timeval tv { .tv_sec = 0, .tv_usec = 100000 };
    const int BUFFER_SIZE = 1024;

    char buffer[BUFFER_SIZE];
    struct sockaddr_un server;

    socket_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (socket_ == -1) {
        LOG("unix domain socket create failed");
        goto errout;
    }

    if (setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        LOG("unix domain socket set timeout failed");
        goto errout;
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, SOCK_PATH);
    unlink(SOCK_PATH);
    if (bind(socket_, (struct sockaddr *)&server, sizeof(server)) == -1) {
        LOG("unix domain socket bind failed");
        goto errout;
    }

    socklen_t len;
    struct sockaddr_un peer;
    running_ = GlobalRunningGet();
    while (running_) {
        len = sizeof(peer);
        int size = recvfrom(socket_, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&peer, &len);
        if (size == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;

            LOG("recvfrom errno=[%d] errmsg=[%s]", errno, strerror(errno));
            goto errout;
        }

        while (size > 0 && isspace(buffer[size - 1]))
            buffer[--size] = 0;

        nlohmann::json data;
        try {
            data = nlohmann::json::parse(buffer);
        } catch (nlohmann::json::parse_error &ex) {
            LOG("parse error, buffer=[%s]", buffer);
            continue;
        }

        if (!data.is_object() || !data["type"].is_string()) {
            LOG("invalid request, buffer=[%s]", buffer);
            continue;
        }

        Session session = NewUserSession();
        UserID client = std::make_shared<struct sockaddr_un>(peer);
        UserConn conn(client, len);
        ConnCache::GetInstance().Put(session, conn);

        nlohmann::json doc;
        doc["session"] = session;
        doc["type"] = std::string(data["type"]);
        doc["data"] = data;
        Broadcaster::GetInstance().Notify(doc.dump());
    }

    close(socket_);
    return 0;

errout:
    close(socket_);
    Shutdown();
    return -1;
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
    LOG("IpcExit Exit");
    IpcServer::GetInstance().Stop();
    return;
}

}; // namespace hackernel
