/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/protector.h"
#include "hackernel/broadcaster.h"
#include "hackernel/dispatcher.h"
#include "hackernel/file.h"
#include "hackernel/heartbeat.h"
#include "hackernel/ipc.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include "hackernel/thread.h"
#include "hackernel/timer.h"
#include "nlc/netlink.h"
#include "process/protector.h"
#include <signal.h>
#include <thread>

using namespace hackernel;

static bool is_running = true;

bool get_running_status() {
    return is_running;
}

void stop_server(int code) {
    if (!is_running)
        return;
    is_running = false;

    DBG("exit start, code=[%d]", code);

    // 停止接受外部用户输入
    stop_ipc_server();
    stop_dispatcher();

    // 关闭内核中的功能模块
    disable_file_prot(SYSTEM_SESSION);
    disable_proc_protect(SYSTEM_SESSION);
    disable_net_prot(SYSTEM_SESSION);

    // 关闭心跳,断开与内核的通信
    stop_heartbeat();
    stop_netlink();

    // 关闭定时器
    stop_timer();
    stop_all_receiver();
}

static void handle_signal(int sig) {
    DBG("received signal=[%d], exit now", sig);
    stop_server(HACKERNEL_SIG);
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
    change_thread_name("main");
    register_signal_handler();
    init_netlink_server();
    handshake_with_kernel();
    create_thread([&]() { start_heartbeat(); });
    create_thread([&]() { start_netlink(); });
    create_thread([&]() { start_dispatcher(); });
    create_thread([&]() { start_timer(); });
    create_thread([&]() { start_ipc_server(); });
    create_thread([&]() { start_process_protector(); });
    create_thread([&]() { start_file_protector(); });
    wait_all_thread_exit();
    DBG("exit done");
    return 0;
}
