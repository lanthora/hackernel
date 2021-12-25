#include "dispatcher/handler.h"
#include "hackernel/file.h"
#include "hackernel/net.h"
#include "hackernel/process.h"
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <string>

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

static int UserFileSetCheck(const nlohmann::json &data) {
    if (!data["path"].is_string())
        goto errout;

    if (!data["perm"].is_number_integer())
        goto errout;

    return 0;

errout:
    ERR("invalid argument=[%s]", data.dump().data());
    return -EINVAL;
}

bool UserFileSet(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::file::set")
        return false;

    int32_t session = doc["session"];
    nlohmann::json data = doc["data"];

    if (UserFileSetCheck(data))
        return false;

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

static int UserNetInsertCheck(const nlohmann::json &data) {

    if (!data["id"].is_number_integer())
        goto errout;
    if (!data["priority"].is_number_integer())
        goto errout;
    if (!data["addr"].is_object())
        goto errout;
    if (!data["addr"]["src"].is_object())
        goto errout;
    if (!data["addr"]["src"]["begin"].is_string())
        goto errout;
    if (!data["addr"]["src"]["end"].is_string())
        goto errout;
    if (!data["addr"]["dst"].is_object())
        goto errout;
    if (!data["addr"]["dst"]["begin"].is_string())
        goto errout;
    if (!data["addr"]["dst"]["end"].is_string())
        goto errout;
    if (!data["protocol"].is_object())
        goto errout;
    if (!data["protocol"]["begin"].is_number_integer())
        goto errout;
    if (!data["protocol"]["end"].is_number_integer())
        goto errout;
    if (!data["port"].is_object())
        goto errout;
    if (!data["port"]["src"].is_object())
        goto errout;
    if (!data["port"]["src"]["begin"].is_number_integer())
        goto errout;
    if (!data["port"]["src"]["end"].is_number_integer())
        goto errout;
    if (!data["port"]["dst"].is_object())
        goto errout;
    if (!data["port"]["dst"]["begin"].is_number_integer())
        goto errout;
    if (!data["port"]["dst"]["end"].is_number_integer())
        goto errout;
    if (!data["flags"].is_number_integer())
        goto errout;
    if (!data["response"].is_number_integer())
        goto errout;
    return 0;

errout:
    ERR("invalid argument=[%s]", data.dump().data());
    return -EINVAL;
}

bool UserNetInsert(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::net::insert")
        return false;

    int32_t session = doc["session"];
    nlohmann::json data = doc["data"];
    if (UserNetInsertCheck(data))
        return false;
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

static int UserNetDeleteCheck(const nlohmann::json &data) {
    if (!data["id"].is_number_integer())
        goto errout;
    return 0;
errout:
    ERR("invalid argument=[%s]", data.dump().data());
    return -EINVAL;
}

bool UserNetDelete(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::net::delete")
        return false;

    int32_t session = doc["session"];

    nlohmann::json data = doc["data"];
    if (UserNetDeleteCheck(data))
        return false;

    uint32_t id = data["id"];
    NetPolicyDelete(session, id);
    return true;
}

}; // namespace hackernel
