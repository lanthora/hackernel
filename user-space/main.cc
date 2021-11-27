#include "file.h"
#include "keepalive.h"
#include "net.h"
#include "process.h"
#include <arpa/inet.h>
#include <signal.h>
#include <thread>

static void Shutdown() {
    FileProtectDisable();
    ProcessProtectDisable();
    NetProtectDisable();
    HeartbeatStop();
    NetlinkServerStop();
}

static void SigHandler(int sig) {
    LOG("received signal=[%d], exit now", sig);
    Shutdown();
}

#define PROCESS_PROTECT 1
#define FILE_PROTECT 1
#define NET_PROTECT 1

int main() {
    int error;

    struct sigaction act;
    act.sa_handler = SigHandler;
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

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

    netlink_thread.join();
    heartbeat_thread.join();
    return 0;
}
