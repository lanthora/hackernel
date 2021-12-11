#include "hackernel/broadcaster.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include "hknl/netlink.h"
#include <arpa/inet.h>
#include <signal.h>
#include <thread>

using namespace hackernel;

static void Shutdown() {
    // 停止接受外部用户输入
    IpcExitNotify();

    // 关闭内核中的功能模块
    FileProtectDisable();
    ProcProtectDisable();
    NetProtectDisable();

    // 关闭心跳,断开与内核的通信
    HeartbeatExitNotify();
    NetlinkExitNotify();
}

static void SigHandler(int sig) {
    LOG("received signal=[%d], exit now", sig);
    Shutdown();
}

static void RegSigHandler() {
    struct sigaction act;
    act.sa_handler = SigHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}

int main() {
    RegSigHandler();
    NetlinkServerInit();

    Handshake();
    std::thread heartbeat_thread(HeartbeatWait);
    std::thread netlink_thread(NetlinkWait);
    std::thread ipc_thread(IpcWait);

    netlink_thread.join();
    heartbeat_thread.join();
    ipc_thread.join();
    return 0;
}
