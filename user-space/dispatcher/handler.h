/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DISPATCHER_HANDLER_H
#define DISPATCHER_HANDLER_H

#include <string>

namespace hackernel {

bool handle_proc_prot_enable_msg(const std::string &msg);
bool handle_proc_prot_disable_msg(const std::string &msg);

bool handle_file_prot_enable_msg(const std::string &msg);
bool handle_file_prot_disable_msg(const std::string &msg);
bool handle_file_prot_set_msg(const std::string &msg);

bool handle_net_prot_enable_msg(const std::string &msg);
bool handle_net_prot_disable_msg(const std::string &msg);
bool handle_net_prot_insert_msg(const std::string &msg);
bool handle_net_prot_delete_msg(const std::string &msg);

} // namespace hackernel

#endif
