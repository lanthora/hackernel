/* SPDX-License-Identifier: GPL-2.0-only */
#include "dispatcher/handler.h"
#include "hackernel/file.h"
#include "hackernel/json.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

bool handle_process_protection_enable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::proc::enable")
        return false;

    int32_t session = doc["session"];
    enable_process_protection(session);
    return true;
}

bool handle_process_protection_disable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::proc::disable")
        return false;

    int32_t session = doc["session"];
    disable_process_protection(session);
    return true;
}

bool handle_file_protection_enable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::file::enable")
        return false;

    int32_t session = doc["session"];
    enable_file_protection(session);
    return true;
}

bool handle_file_protection_disable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::file::disable")
        return false;

    int32_t session = doc["session"];
    disable_file_protection(session);
    return true;
}

static int check_user_file_set_data(const nlohmann::json &data) {
    if (!data.contains("path"))
        goto errout;

    if (!data["path"].is_string())
        goto errout;

    if (!data.contains("perm"))
        goto errout;

    if (!data["perm"].is_number_integer())
        goto errout;

    if (!data.contains("flag"))
        goto errout;

    if (!data["flag"].is_number_integer())
        goto errout;
    return 0;

errout:
    WARN("invalid argument=[%s]", json::dump(data).data());
    return -EINVAL;
}

bool handle_file_protection_set_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::file::set")
        return false;

    int32_t session = doc["session"];
    nlohmann::json data = doc["data"];

    if (check_user_file_set_data(data))
        return false;

    std::string path = data["path"];
    int32_t perm = data["perm"];
    int flag = data["flag"];
    set_file_protection(session, path.data(), perm, flag);
    return true;
}

bool handle_file_protection_clear_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::file::clear")
        return false;

    int32_t session = doc["session"];
    clear_file_protection(session);
    return true;
}

bool handle_net_protection_enable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::net::enable")
        return false;

    int32_t session = doc["session"];
    enable_net_protection(session);
    return true;
}

bool handle_net_protection_disable_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::net::disable")
        return false;

    int32_t session = doc["session"];
    disable_net_protection(session);
    return true;
}

static int check_net_protection_insert_data(const nlohmann::json &data) {
    if (!data.contains("id"))
        goto errout;
    if (!data["id"].is_number_integer())
        goto errout;
    if (!data.contains("priority"))
        goto errout;
    if (!data["priority"].is_number_integer())
        goto errout;
    if (!data.contains("addr"))
        goto errout;
    if (!data["addr"].contains("src"))
        goto errout;
    if (!data["addr"]["src"].contains("begin"))
        goto errout;
    if (!data["addr"]["src"]["begin"].is_string())
        goto errout;
    if (!data["addr"]["src"].contains("end"))
        goto errout;
    if (!data["addr"]["src"]["end"].is_string())
        goto errout;
    if (!data["addr"].contains("dst"))
        goto errout;
    if (!data["addr"]["dst"].contains("begin"))
        goto errout;
    if (!data["addr"]["dst"]["begin"].is_string())
        goto errout;
    if (!data["addr"]["dst"].contains("end"))
        goto errout;
    if (!data["addr"]["dst"]["end"].is_string())
        goto errout;
    if (!data.contains("protocol"))
        goto errout;
    if (!data["protocol"].contains("begin"))
        goto errout;
    if (!data["protocol"]["begin"].is_number_integer())
        goto errout;
    if (!data["protocol"].contains("end"))
        goto errout;
    if (!data["protocol"]["end"].is_number_integer())
        goto errout;
    if (!data.contains("port"))
        goto errout;
    if (!data["port"].contains("src"))
        goto errout;
    if (!data["port"]["src"].contains("begin"))
        goto errout;
    if (!data["port"]["src"]["begin"].is_number_integer())
        goto errout;
    if (!data["port"]["src"].contains("end"))
        goto errout;
    if (!data["port"]["src"]["end"].is_number_integer())
        goto errout;
    if (!data["port"].contains("dst"))
        goto errout;
    if (!data["port"]["dst"].contains("begin"))
        goto errout;
    if (!data["port"]["dst"]["begin"].is_number_integer())
        goto errout;
    if (!data["port"]["dst"].contains("end"))
        goto errout;
    if (!data["port"]["dst"]["end"].is_number_integer())
        goto errout;
    if (!data.contains("flags"))
        goto errout;
    if (!data["flags"].is_number_integer())
        goto errout;
    if (!data.contains("response"))
        goto errout;
    if (!data["response"].is_number_integer())
        goto errout;
    return 0;

errout:
    WARN("invalid argument=[%s]", json::dump(data).data());
    return -EINVAL;
}

bool handle_net_protection_insert_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::net::insert")
        return false;

    int32_t session = doc["session"];
    nlohmann::json data = doc["data"];
    if (check_net_protection_insert_data(data))
        return false;
    net_policy policy;
    policy.id = data["id"];
    policy.priority = data["priority"];
    policy.addr.src.begin = ntohl(inet_addr(std::string(data["addr"]["src"]["begin"]).data()));
    policy.addr.src.end = ntohl(inet_addr(std::string(data["addr"]["src"]["end"]).data()));
    policy.addr.dst.begin = ntohl(inet_addr(std::string(data["addr"]["dst"]["begin"]).data()));
    policy.addr.dst.end = ntohl(inet_addr(std::string(data["addr"]["dst"]["end"]).data()));
    policy.protocol.begin = data["protocol"]["begin"];
    policy.protocol.end = data["protocol"]["end"];
    policy.port.src.begin = data["port"]["src"]["begin"];
    policy.port.src.end = data["port"]["src"]["end"];
    policy.port.dst.begin = data["port"]["dst"]["begin"];
    policy.port.dst.end = data["port"]["dst"]["end"];
    policy.flags = data["flags"];
    policy.response = data["response"];

    insert_net_policy(session, &policy);
    return true;
}

static int check_net_protection_delete_data(const nlohmann::json &data) {
    if (!data.contains("id"))
        goto errout;
    if (!data["id"].is_number_integer())
        goto errout;
    return 0;

errout:
    WARN("invalid argument=[%s]", json::dump(data).data());
    return -EINVAL;
}

bool handle_net_protection_delete_msg(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] != "user::net::delete")
        return false;

    int32_t session = doc["session"];

    nlohmann::json data = doc["data"];
    if (check_net_protection_delete_data(data))
        return false;

    uint32_t id = data["id"];
    delete_net_policy(session, id);
    return true;
}

}; // namespace hackernel
