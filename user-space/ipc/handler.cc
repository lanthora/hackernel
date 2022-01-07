/* SPDX-License-Identifier: GPL-2.0-only */
#include "ipc/handler.h"
#include "hackernel/ipc.h"
#include "ipc/server.h"
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

using namespace ipc;

static int UserMsgSubCheck(const nlohmann::json &data) {
    if (!data["section"].is_string())
        goto errout;

    return 0;

errout:
    ERR("invalid argument=[%s]", data.dump().data());
    ;
    return -EINVAL;
}

bool UserMsgSub(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::msg::sub")
        return false;

    UserConn conn;
    if (IpcServer::GetConnCache().Get(doc["session"], conn))
        return false;

    nlohmann::json data = doc["data"];
    if (UserMsgSubCheck(data))
        return false;
    const std::string &section = data["section"];

    data["code"] = IpcServer::GetInstance().MsgSub(section, conn);
    IpcServer::GetInstance().SendMsgToClient(doc["session"], data.dump());
    return true;
}

static int UserMsgUnsubCheck(const nlohmann::json &data) {
    if (!data["section"].is_string())
        goto errout;

    return 0;

errout:
    ERR("invalid argument=[%s]", data.dump().data());
    return -EINVAL;
}

bool UserMsgUnsub(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::msg::unsub")
        return false;

    UserConn conn;
    if (IpcServer::GetConnCache().Get(doc["session"], conn))
        return false;

    nlohmann::json data = doc["data"];
    if (UserMsgUnsubCheck(data))
        return false;
    const std::string &section = data["section"];

    data["code"] = IpcServer::GetInstance().MsgUnsub(section, conn);
    IpcServer::GetInstance().SendMsgToClient(doc["session"], data.dump());
    return true;
}

bool UserCtrlExit(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::ctrl::exit")
        return false;

    Shutdown();
    return true;
}

static int UserCtrlTokenCheck(const nlohmann::json &data) {
    if (!data["new"].is_string())
        goto errout;

    return 0;

errout:
    ERR("invalid argument=[%s]", data.dump().data());
    return -EINVAL;
}

bool UserCtrlToken(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::ctrl::token")
        return false;

    nlohmann::json data = doc["data"];
    if (UserCtrlTokenCheck(data))
        return false;
    std::string token = data["new"];

    data["code"] = IpcServer::GetInstance().TokenUpdate(token);
    IpcServer::GetInstance().SendMsgToClient(doc["session"], data.dump());
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

bool AuditProcReport(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "audit::proc::report")
        return false;

    std::string section = doc["type"];
    nlohmann::json data = doc["data"];
    IpcServer::GetInstance().SendMsgToSubscriber(section, data.dump());
    return true;
}

}; // namespace hackernel
