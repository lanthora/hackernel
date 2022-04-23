/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DISPATCHER_HANDLER_H
#define DISPATCHER_HANDLER_H

#include <string>

namespace hackernel {

bool handle_process_protection_enable_msg(const std::string &msg);
bool handle_process_protection_disable_msg(const std::string &msg);

bool handle_file_protection_enable_msg(const std::string &msg);
bool handle_file_protection_disable_msg(const std::string &msg);
bool handle_file_protection_set_msg(const std::string &msg);

bool handle_net_protection_enable_msg(const std::string &msg);
bool handle_net_protection_disable_msg(const std::string &msg);
bool handle_net_protection_insert_msg(const std::string &msg);
bool handle_net_protection_delete_msg(const std::string &msg);

} // namespace hackernel

#endif
