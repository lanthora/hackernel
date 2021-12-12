#include "hackernel/broadcaster.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <thread>

namespace hackernel {

#define PROCESS_PROTECT 1
#define FILE_PROTECT 0
#define NET_PROTECT 0

int IpcTest() {
    LOG("IPC Server Start");

#if PROCESS_PROTECT
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

std::shared_ptr<Receiver> ipc_broadcast_receiver;

static int StringSplit(std::string text, const std::string &delimiter, std::vector<std::string> &output) {
    size_t pos = 0;
    output.clear();
    while ((pos = text.find(delimiter)) != std::string::npos) {
        output.push_back(text.substr(0, pos));
        text.erase(0, pos + delimiter.length());
    }
    if (text.size()) {
        output.push_back(text);
    }
    return 0;
}

static bool ProcReport(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::report")
        return false;

    std::vector<std::string> detal;
    StringSplit(std::string(doc["cmd"]), "\37", detal);
    std::cout << "kernel::proc::report, workdir=[" << detal[0] << "] path=[" << detal[1] << "] argv=[" << detal[2];
    for (int i = 3; i < detal.size(); ++i) {
        std::cout << " " << detal[i];
    }
    std::cout << "]" << std::endl;

    return true;
}

static bool ProcStatus(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] == "kernel::proc::enable") {
        std::cout << "kernel::proc::enable, ";
        std::cout << "session=[" << doc["session"] << "] ";
        std::cout << "code=[" << doc["code"] << "] ";
        std::cout << std::endl;
        return true;
    }
    if (doc["type"] == "kernel::proc::disable") {
        std::cout << "kernel::proc::disable, ";
        std::cout << "session=[" << doc["session"] << "] ";
        std::cout << "code=[" << doc["code"] << "] ";
        std::cout << std::endl;
        return true;
    }
    return false;
}

int IpcWait() {
    IpcTest();

    ipc_broadcast_receiver = std::make_shared<Receiver>();
    ipc_broadcast_receiver->AddHandler(ProcReport);
    ipc_broadcast_receiver->AddHandler(ProcStatus);
    Broadcaster::GetInstance().AddReceiver(ipc_broadcast_receiver);
    ipc_broadcast_receiver->ConsumeWait();
    return 0;
}

void IpcExitNotify() {
    LOG("IPC Server Exit");
    ipc_broadcast_receiver->ExitNotify();
    return;
}
}; // namespace hackernel
