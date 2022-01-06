/* SPDX-License-Identifier: GPL-2.0 */
#include "hackernel/broadcaster.h"
#include "hackernel/dispatcher.h"
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

static bool running = true;

bool GlobalRunningGet() {
    return running;
}

void Shutdown() {
    LOG("shutdown");
    if (!running)
        return;
    running = false;

    // 停止接受外部用户输入
    IpcExit();
    DispatcherExit();

    // 关闭内核中的功能模块
    FileProtectDisable(SYSTEM_SESSION);
    ProcProtectDisable(SYSTEM_SESSION);
    NetProtectDisable(SYSTEM_SESSION);

    // 关闭心跳,断开与内核的通信
    HeartbeatExit();
    NetlinkExit();
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
    ThreadNameUpdate("main");
    RegSigHandler();
    NetlinkServerInit();

    Handshake();
    std::thread heartbeat_thread(HeartbeatWait);
    std::thread netlink_thread(NetlinkWait);
    std::thread dispatcher_thread(DispatcherWait);
    std::thread ipc_thread(IpcWait);

    netlink_thread.join();
    heartbeat_thread.join();
    dispatcher_thread.join();
    ipc_thread.join();

    return 0;
}
