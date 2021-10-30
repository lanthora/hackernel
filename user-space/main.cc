#include "exclusive.h"
#include "file.h"
#include "net.h"
#include "process.h"
#include <arpa/inet.h>
#include <signal.h>
#include <thread>

void SigHandler(int sig) {
    LOG("received signal, exit now");
    FileProtectDisable();
    ProcessProtectDisable();
    DisableNetProtect();
    HeartbeatStop();
    StopNetlinkServer();
}

#define PROCESS_PROTECT 1
#define FILE_PROTECT 1
#define NET_PROTECT 1

#define FLAG_INBOUND (1U << 0)
#define FLAG_OUTBOUND (1U << 1)
#define FLAG_TCP_HANDSHAKE (1U << 2)
#define FLAG_TCP_HEADER_ONLY (1U << 3)

int main() {
    int error;

    signal(SIGINT, SigHandler);
    signal(SIGTERM, SigHandler);

    error = NetlinkServerInit();
    if (error) {
        LOG("init netlink failed. exit");
        exit(1);
    }

    std::thread netlink_thread(NetlinkServerStart);

    Handshake();

    std::thread heartbeat_thread(HeartbeatStart);

#if PROCESS_PROTECT
    ProcessProtectEnable();
#endif

#if FILE_PROTECT
    FileProtectEnable();
    FileProtectSet("/etc/fstab", ALL_FILE_PROTECT_FLAG - READ_PROTECT_FLAG);
    FileProtectSet("/boot/grub/grub.cfg", ALL_FILE_PROTECT_FLAG);
    FileProtectSet("/etc/host.conf", ALL_FILE_PROTECT_FLAG - READ_PROTECT_FLAG);
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
    policy.flags = FLAG_INBOUND;
    policy.response = NET_POLICY_ACCEPT;
    NetPolicyInsert(&policy);

    policy.port.src.begin = 22;
    policy.port.src.end = 22;
    policy.port.dst.begin = 0;
    policy.port.dst.end = UINT16_MAX;
    policy.flags = FLAG_OUTBOUND;
    policy.response = NET_POLICY_ACCEPT;
    NetPolicyInsert(&policy);

    // allow tcp header
    policy.port.src.begin = 0;
    policy.port.src.end = UINT16_MAX;
    policy.port.dst.begin = 0;
    policy.port.dst.end = UINT16_MAX;
    policy.id = 1;
    policy.priority = 1;
    policy.flags = FLAG_OUTBOUND | FLAG_TCP_HEADER_ONLY;
    policy.response = NET_POLICY_ACCEPT;
    NetPolicyInsert(&policy);

    // allow localhost
    policy.addr.src.begin = ntohl(inet_addr("127.0.0.1"));
    policy.addr.src.end = ntohl(inet_addr("127.0.0.1"));
    policy.addr.dst.begin = ntohl(inet_addr("127.0.0.1"));
    policy.addr.dst.end = ntohl(inet_addr("127.0.0.1"));
    policy.flags = FLAG_INBOUND | FLAG_OUTBOUND;
    NetPolicyInsert(&policy);

    // docker
    policy.addr.src.begin = ntohl(inet_addr("172.17.0.0"));
    policy.addr.src.end = ntohl(inet_addr("172.17.255.255"));
    policy.addr.dst.begin = ntohl(inet_addr("172.17.0.0"));
    policy.addr.dst.end = ntohl(inet_addr("172.17.255.255"));
    policy.flags = FLAG_INBOUND | FLAG_OUTBOUND;
    NetPolicyInsert(&policy);

    // disable others
    policy.addr.src.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.src.end = ntohl(inet_addr("255.255.255.255"));
    policy.addr.dst.begin = ntohl(inet_addr("0.0.0.0"));
    policy.addr.dst.end = ntohl(inet_addr("255.255.255.255"));
    policy.id = 2;
    policy.priority = 2;
    policy.flags = FLAG_OUTBOUND;
    policy.response = NET_POLICY_DROP;
    NetPolicyInsert(&policy);
#endif

    netlink_thread.join();
    heartbeat_thread.join();
    return 0;
}
