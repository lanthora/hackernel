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
    update_thread_name("dispatcher");

    dispatcher = std::make_shared<audience>();
    dispatcher->add_message_handler(handle_process_protection_enable_msg);
    dispatcher->add_message_handler(handle_process_protection_disable_msg);
    dispatcher->add_message_handler(handle_file_protection_enable_msg);
    dispatcher->add_message_handler(handle_file_protection_disable_msg);
    dispatcher->add_message_handler(handle_file_protection_set_msg);
    dispatcher->add_message_handler(handle_net_protection_enable_msg);
    dispatcher->add_message_handler(handle_net_protection_disable_msg);
    dispatcher->add_message_handler(handle_net_protection_insert_msg);
    dispatcher->add_message_handler(handle_net_protection_delete_msg);

    broadcaster::global().add_audience(dispatcher);
    DBG("dispatcher enter");
    dispatcher->start_consuming_message();
    DBG("dispatcher exit");
    return 0;
}

void stop_dispatcher() {
    if (dispatcher)
        dispatcher->stop_consuming_message();
}

}; // namespace hackernel
