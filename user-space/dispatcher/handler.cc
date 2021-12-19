#include "hackernel/dispatcher.h"
#include "hackernel/file.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include <arpa/inet.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace hackernel {

bool UserProcEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::proc::enable")
        return false;

    int32_t session = doc["session"];
    ProcProtectEnable(session);
    return true;
}

bool UserProcDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::proc::disable")
        return false;

    int32_t session = doc["session"];
    ProcProtectDisable(session);
    return true;
}

bool UserFileEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::file::enable")
        return false;

    int32_t session = doc["session"];
    FileProtectEnable(session);
    return true;
}

bool UserFileDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::file::disable")
        return false;

    int32_t session = doc["session"];
    FileProtectDisable(session);
    return true;
}

bool UserFileSet(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::file::set")
        return false;

    int32_t session = doc["session"];
    nlohmann::json data = doc["data"];

    std::string path = data["path"];
    int32_t perm = data["perm"];
    FileProtectSet(session, path.data(), perm);
    return true;
}

bool UserNetEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::net::enable")
        return false;

    int32_t session = doc["session"];
    NetProtectEnable(session);
    return true;
}

bool UserNetDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::net::disable")
        return false;

    int32_t session = doc["session"];
    NetProtectDisable(session);
    return true;
}

bool UserNetInsert(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::net::insert")
        return false;

    int32_t session = doc["session"];
    nlohmann::json data = doc["data"];
    NetPolicy policy;
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

    NetPolicyInsert(session, &policy);
    return true;
}

bool UserNetDelete(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::net::delete")
        return false;

    int32_t session = doc["session"];

    nlohmann::json data = doc["data"];
    uint32_t id = data["id"];
    NetPolicyDelete(session, id);
    return true;
}

}; // namespace hackernel
