#include "hackernel/ipc.h"
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

bool UserMsgSub(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::msg::sub")
        return false;

    UserConn conn;
    ConnCache::GetInstance().Get(doc["session"], conn);
    IpcServer::GetInstance().MsgSub(doc["data"]["section"], conn);
    doc["data"]["code"] = 0;
    IpcServer::GetInstance().SendMsgToClient(doc["session"], doc["data"].dump());
    return true;
}

bool UserMsgUnsub(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::msg::unsub")
        return false;

    UserConn conn;
    ConnCache::GetInstance().Get(doc["session"], conn);
    IpcServer::GetInstance().MsgUnsub(doc["data"]["section"], conn);
    doc["data"]["code"] = 0;
    IpcServer::GetInstance().SendMsgToClient(doc["session"], doc["data"].dump());
    return true;
}

bool KernelProcReport(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::report")
        return false;

    std::string section = doc["type"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToSubscriber(section, data.dump());
    return true;
}

bool KernelProcEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::enable")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}

bool KernelProcDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::disable")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}

bool KernelFileReport(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::file::report")
        return false;

    std::string section = doc["type"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToSubscriber(section, data.dump());
    return true;
}

bool KernelFileSet(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::file::set")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}
bool KernelFileEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::file::enable")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}

bool KernelFileDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::file::disable")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}

bool KernelNetInsert(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::net::insert")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}

bool KernelNetDelete(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::net::delete")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}
bool KernelNetEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::net::enable")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}
bool KernelNetDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::net::disable")
        return false;

    Session session = doc["session"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToClient(session, data.dump());
    return true;
}

}; // namespace hackernel
