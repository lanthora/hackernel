/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/protector.h"
#include "hackernel/broadcaster.h"
#include "hackernel/dispatcher.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "hackernel/osinfo.h"
#include "hackernel/process.h"
#include "hackernel/thread.h"
#include "hackernel/timer.h"
#include "nlc/netlink.h"
#include "process/protector.h"
#include <atomic>
#include <signal.h>
#include <thread>

using namespace hackernel;

static std::atomic<bool> running = true;

bool current_service_status() {
    return running.load();
}

void shutdown_service(int status_code) {
    if (!running.exchange(false))
        return;

    DBG("exit start, status_code=[%d]", status_code);

    // 停止接受外部用户输入
    stop_ipc_server();
    stop_dispatcher();

    // 关闭内核中的功能模块
    disable_file_protection(SYSTEM_SESSION);
    disable_process_protection(SYSTEM_SESSION);
    disable_net_protection(SYSTEM_SESSION);

    // 关闭心跳,断开与内核的通信
    stop_heartbeat();
    stop_netlink();

    // 关闭定时器
    stop_timer();
    stop_all_audience();
}

static void handle_signal(int sig) {
    DBG("received signal=[%d], exit now", sig);
    shutdown_service(HACKERNEL_SIG);
}

static void register_signal_handler() {
    struct sigaction act;
    act.sa_handler = handle_signal;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}

int main() {
    update_thread_name("main");
    register_signal_handler();
    register_osinfo_timer();
    init_netlink_server();
    handshake_with_kernel();
    create_thread([&]() { start_heartbeat(); });
    create_thread([&]() { start_netlink(); });
    create_thread([&]() { start_dispatcher(); });
    create_thread([&]() { start_timer(); });
    create_thread([&]() { start_ipc_server(); });
    create_thread([&]() { start_process_protector(); });
    create_thread([&]() { start_file_protector(); });
    wait_thread_exit();
    DBG("exit done");
    return 0;
}
