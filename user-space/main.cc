/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/audit.h"
#include "hackernel/broadcaster.h"
#include "hackernel/dispatcher.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include "hackernel/threads.h"
#include "hackernel/timer.h"
#include "nlc/netlink.h"
#include "process/audit.h"
#include <arpa/inet.h>
#include <signal.h>
#include <thread>

using namespace hackernel;

static bool running = true;

bool RUNNING() {
    return running;
}

void SHUTDOWN(int code) {
    if (!running)
        return;
    running = false;

    DBG("exit start ,code=[%d]", code);

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

    // 关闭定时器
    TimerExit();
}

static void SigHandler(int sig) {
    DBG("received signal=[%d], exit now", sig);
    SHUTDOWN(HACKERNEL_SIG);
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
    std::thread timer_thread(TimerWait);
    std::thread ipc_thread(IpcWait);

    process::Auditor::GetInstance().Init();
    file::Auditor::GetInstance().Init();

    heartbeat_thread.join();
    netlink_thread.join();
    dispatcher_thread.join();
    timer_thread.join();
    ipc_thread.join();

    Broadcaster::GetInstance().ExitAllReceiver();
    Threads::GetInstance().WaitAllThreadsExit();
    DBG("exit done");

    return 0;
}
