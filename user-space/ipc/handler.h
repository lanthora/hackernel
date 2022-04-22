/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IPC_HANDLER_H
#define IPC_HANDLER_H

#include <string>

namespace hackernel {

bool handle_user_sub_msg(const std::string &msg);
bool handle_user_unsub_msg(const std::string &msg);
bool handle_user_ctrl_exit_msg(const std::string &msg);
bool handle_user_ctrl_token_msg(const std::string &msg);
bool handle_user_test_echo_msg(const std::string &msg);

bool handle_kernel_proc_report_msg(const std::string &msg);
bool handle_kernel_proc_enable_msg(const std::string &msg);
bool handle_kernel_proc_disable_msg(const std::string &msg);

bool handle_kernel_file_report_msg(const std::string &msg);
bool handle_kernel_file_set_msg(const std::string &msg);
bool handle_kernel_file_enable_msg(const std::string &msg);
bool handle_kernel_file_disable_msg(const std::string &msg);

bool handle_kernel_net_insert_msg(const std::string &msg);
bool handle_kernel_net_delete_msg(const std::string &msg);
bool handle_kernel_net_enable_msg(const std::string &msg);
bool handle_kernel_net_disable_msg(const std::string &msg);

bool handle_audit_proc_report_msg(const std::string &msg);

}; // namespace hackernel

#endif
