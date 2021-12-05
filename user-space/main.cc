#include "file.h"
#include "ipc.h"
#include "keepalive.h"
#include "net.h"
#include "netlink.h"
#include "process.h"
#include <arpa/inet.h>
#include <signal.h>
#include <thread>

static void Shutdown() {
    IpcStop();
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

static void RegSigHandler() {
    struct sigaction act;
    act.sa_handler = SigHandler;
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}

int main() {
    RegSigHandler();
    NetlinkServerInit();

    // 由于NetlinkServerInit已经初始化好了Netlink接收缓冲区,
    // 先启动发送消息的线程还是先启动接收消息的线程都不会影响程序正常运行
    // 所以这三个线程的启动顺序无关紧要
    std::thread netlink_thread(NetlinkServerStart);
    std::thread heartbeat_thread(HeartbeatStart);
    std::thread ipc_thread(IpcStart);

    netlink_thread.join();
    heartbeat_thread.join();
    ipc_thread.join();
    return 0;
}
