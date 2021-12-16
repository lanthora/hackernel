#include "hackernel/broadcaster.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include <arpa/inet.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace hackernel {

IpcServer &IpcServer::GetInstance() {
    static IpcServer instance;
    return instance;
}
int IpcServer::Init() {
    receiver_ = std::make_shared<Receiver>();
    receiver_->AddHandler([](const std::string &msg) {
        nlohmann::json doc = nlohmann::json::parse(msg);
        if (doc["type"] == "kernel::proc::enable") {
            // TODO: 根据session字段发送给对应客户端
            std::cout << msg << std::endl;
            return true;
        }
        if (doc["type"] == "kernel::proc::disable") {
            std::cout << msg << std::endl;
            return true;
        }
        return false;
    });
    Broadcaster::GetInstance().AddReceiver(receiver_);
    return 0;
}

int IpcServer::UnixDomainSocketWait() {
    return 0;
}

// 需要开两个线程,receiver_消费线程和socket接收消息的线程
int IpcServer::StartWait() {
    std::thread receiver_thread([&]() {
        ThreadNameUpdate("ipc-recevier");
        LOG("ipc-recevier enter");
        receiver_->ConsumeWait();
        LOG("ipc-recevier exit");
    });
    std::thread uds_thread([&]() {
        ThreadNameUpdate("ipc-socket");
        LOG("ipc-socket enter");
        UnixDomainSocketWait();
        LOG("ipc-socket exit");
    });

    receiver_thread.join();
    uds_thread.join();
    return 0;
}

int IpcServer::Stop() {
    running_ = false;
    if (receiver_)
        receiver_->Exit();
    return 0;
}

#define PROCESS_PROTECT 1
#define FILE_PROTECT 0
#define NET_PROTECT 0

int IpcTest() {
    LOG("IpcTest Start");

#if PROCESS_PROTECT
    // 测试过程中, 广播发送成功后处理广播的线程还没开始工作, 造成整个进程阻塞的假象, 实际上所有线程都在正常工作,
    // 只是命令没有下发给内核
    nlohmann::json doc;
    doc["session"] = 0;
    doc["type"] = "user::proc::enable";
    Broadcaster::GetInstance().Notify(doc.dump());

    // 所以在这里补一个函数调用, 确保命令能下发成功. 在现实的使用场景中, 用户下发的命令会收到响应以判断命令是否下发成功
    ProcProtectEnable();
#endif

#if FILE_PROTECT
    FileProtectEnable();
    FileProtectSet("/etc/fstab", FLAG_FILE_READ_ONLY);
    FileProtectSet("/boot/grub/grub.cfg", FLAG_FILE_ALL_DISABLE);
    FileProtectSet("/etc/host.conf", FLAG_FILE_READ_ONLY);
#endif

#if NET_PROTECT
    NetProtectEnable();

    NetPolicy policy;
    policy.addr.src.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.src.end = ntohl(inet_addr("255.255.255.255"));
    policy.addr.dst.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.dst.end = ntohl(inet_addr("255.255.255.255"));
    policy.protocol.begin = 6;
    policy.protocol.end = 6;

    // allow ssh
    policy.port.src.begin = 0;
    policy.port.src.end = UINT16_MAX;
    policy.port.dst.begin = 22;
    policy.port.dst.end = 22;

    policy.id = 0;
    policy.priority = 0;
    policy.flags = FLAG_NET_INBOUND;
    policy.response = NET_POLICY_ACCEPT;
    NetPolicyInsert(&policy);

    policy.port.src.begin = 22;
    policy.port.src.end = 22;
    policy.port.dst.begin = 0;
    policy.port.dst.end = UINT16_MAX;
    policy.flags = FLAG_NET_OUTBOUND;
    policy.response = NET_POLICY_ACCEPT;
    NetPolicyInsert(&policy);

    // allow tcp header
    policy.port.src.begin = 0;
    policy.port.src.end = UINT16_MAX;
    policy.port.dst.begin = 0;
    policy.port.dst.end = UINT16_MAX;
    policy.id = 1;
    policy.priority = 1;
    policy.flags = FLAG_NET_OUTBOUND | FLAG_NET_ONLY_ALLOW_TCP_HEADER;
    policy.response = NET_POLICY_ACCEPT;
    NetPolicyInsert(&policy);

    // allow localhost
    policy.addr.src.begin = ntohl(inet_addr("127.0.0.1"));
    policy.addr.src.end = ntohl(inet_addr("127.0.0.1"));
    policy.addr.dst.begin = ntohl(inet_addr("127.0.0.1"));
    policy.addr.dst.end = ntohl(inet_addr("127.0.0.1"));
    policy.flags = FLAG_NET_INBOUND | FLAG_NET_OUTBOUND;
    NetPolicyInsert(&policy);

    // docker
    policy.addr.src.begin = ntohl(inet_addr("172.17.0.0"));
    policy.addr.src.end = ntohl(inet_addr("172.17.255.255"));
    policy.addr.dst.begin = ntohl(inet_addr("172.17.0.0"));
    policy.addr.dst.end = ntohl(inet_addr("172.17.255.255"));
    policy.flags = FLAG_NET_INBOUND | FLAG_NET_OUTBOUND;
    NetPolicyInsert(&policy);

    // disable others
    policy.addr.src.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.src.end = ntohl(inet_addr("255.255.255.255"));
    policy.addr.dst.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.dst.end = ntohl(inet_addr("255.255.255.255"));
    policy.id = 2;
    policy.priority = 2;
    policy.flags = FLAG_NET_OUTBOUND;
    policy.response = NET_POLICY_DROP;
    NetPolicyInsert(&policy);
#endif

    return 0;
}

int IpcWait() {
    IpcServer::GetInstance().Init();
    IpcTest();
    IpcServer::GetInstance().StartWait();

    return 0;
}

void IpcExit() {
    LOG("IpcExit Exit");
    IpcServer::GetInstance().Stop();
    return;
}
}; // namespace hackernel
