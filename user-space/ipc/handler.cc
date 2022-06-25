/* SPDX-License-Identifier: GPL-2.0-only */
#include "ipc/handler.h"
#include "hackernel/ipc.h"
#include "hackernel/json.h"
#include "ipc/server.h"
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

using namespace ipc;

bool handle_user_test_echo_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::test::echo")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

static int UserMsgSubCheck(const nlohmann::json &data) {
    if (!data["section"].is_string())
        goto errout;

    return 0;

errout:
    WARN("invalid argument=[%s]", json::dump(data).data());
    return -EINVAL;
}

bool handle_user_sub_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::msg::sub")
        return false;

    user_conn conn;
    if (ipc_server::global().clients.get(doc["session"], conn))
        return false;

    nlohmann::json &data = doc["data"];
    if (UserMsgSubCheck(data))
        return false;
    const std::string &section = data["section"];

    data["code"] = ipc_server::global().handle_msg_sub(section, conn);
    ipc_server::global().send_msg_to_client(doc);
    return true;
}

static int check_user_msg_unsub_data(const nlohmann::json &data) {
    if (!data.contains("section"))
        goto errout;
    if (!data["section"].is_string())
        goto errout;

    return 0;

errout:
    WARN("invalid argument=[%s]", json::dump(data).data());
    return -EINVAL;
}

bool handle_user_unsub_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::msg::unsub")
        return false;

    user_conn conn;
    if (ipc_server::global().clients.get(doc["session"], conn))
        return false;

    nlohmann::json &data = doc["data"];
    if (check_user_msg_unsub_data(data))
        return false;
    const std::string &section = data["section"];

    data["code"] = ipc_server::global().handle_msg_unsub(section, conn);
    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_user_ctrl_exit_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::ctrl::exit")
        return false;

    shutdown_service(HACKERNEL_SUCCESS);
    return true;
}

static int check_user_ctrl_token_data(const nlohmann::json &data) {
    if (!data.contains("new"))
        goto errout;
    if (!data["new"].is_string())
        goto errout;
    return 0;

errout:
    WARN("invalid argument=[%s]", json::dump(data).data());
    return -EINVAL;
}

bool handle_user_ctrl_token_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::ctrl::token")
        return false;

    nlohmann::json &data = doc["data"];
    if (check_user_ctrl_token_data(data))
        return false;
    std::string token = data["new"];

    data["code"] = ipc_server::global().update_token(token);
    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_kernel_process_report_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::proc::report")
        return false;

    ipc_server::global().broadcast_msg_to_subscriber(doc);
    return true;
}

bool handle_kernel_process_enable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::proc::enable")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_kernel_process_disable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::proc::disable")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_kernel_file_report_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::file::report")
        return false;

    ipc_server::global().broadcast_msg_to_subscriber(doc);
    return true;
}

bool handle_kernel_file_set_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::file::set")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}
bool handle_kernel_file_enable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::file::enable")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_kernel_file_disable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::file::disable")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_kernel_net_insert_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::net::insert")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_kernel_net_delete_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::net::delete")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}
bool handle_kernel_net_enable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::net::enable")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}
bool handle_kernel_net_disable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "kernel::net::disable")
        return false;

    ipc_server::global().send_msg_to_client(doc);
    return true;
}

bool handle_audit_process_report_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "audit::proc::report")
        return false;

    ipc_server::global().broadcast_msg_to_subscriber(doc);
    return true;
}

bool handle_osinfo_report_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "osinfo::report")
        return false;

    ipc_server::global().broadcast_msg_to_subscriber(doc);
    return true;
}

}; // namespace hackernel
