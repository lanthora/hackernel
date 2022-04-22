/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/dispatcher.h"
#include "dispatcher/handler.h"
#include "hackernel/broadcaster.h"
#include "hackernel/json.h"
#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <unordered_set>

namespace hackernel {

static std::shared_ptr<audience> dispatcher = nullptr;

int start_dispatcher() {
    change_thread_name("dispatcher");

    dispatcher = std::make_shared<audience>();
    dispatcher->add_msg_handler(handle_proc_prot_enable_msg);
    dispatcher->add_msg_handler(handle_proc_prot_disable_msg);
    dispatcher->add_msg_handler(handle_file_prot_enable_msg);
    dispatcher->add_msg_handler(handle_file_prot_disable_msg);
    dispatcher->add_msg_handler(handle_file_prot_set_msg);
    dispatcher->add_msg_handler(handle_net_prot_enable_msg);
    dispatcher->add_msg_handler(handle_net_prot_disable_msg);
    dispatcher->add_msg_handler(handle_net_prot_insert_msg);
    dispatcher->add_msg_handler(handle_net_prot_delete_msg);

    broadcaster::global().add_audience(dispatcher);
    DBG("dispatcher enter");
    dispatcher->start_consume_msg();
    DBG("dispatcher exit");
    return 0;
}

void stop_dispatcher() {
    if (dispatcher)
        dispatcher->stop_consume_msg();
}

}; // namespace hackernel
