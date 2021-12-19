#include "hackernel/ipc.h"
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace hackernel {

static int StringSplit(std::string text, const std::string &delimiter, std::vector<std::string> &output) {
    size_t pos = 0;
    output.clear();
    while ((pos = text.find(delimiter)) != std::string::npos) {
        output.push_back(text.substr(0, pos));
        text.erase(0, pos + delimiter.length());
    }
    if (text.size()) {
        output.push_back(text);
    }
    return 0;
}

bool KernelProcReport(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::report")
        return false;

    std::vector<std::string> detal;
    StringSplit(std::string(doc["data"]["cmd"]), "\u001f", detal);
    std::string workdir = detal[0];
    std::string path = detal[1];
    std::string argv = detal[2];
    for (size_t i = 3; i < detal.size(); ++i) {
        argv += " ";
        argv += detal[i];
    }
    printf("kernel::proc::report, workdir=[%s] path=[%s] argv=[%s]\n", workdir.data(), path.data(), argv.data());

    return true;
}

bool KernelProcEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::enable")
        return false;

    Session session = doc["session"];
    std::string data = doc["data"].dump();
    IpcServer::GetInstance().SendMsgToClient(session, data);
    return true;
}

bool KernelProcDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "kernel::proc::disable")
        return false;

    Session session = doc["session"];
    std::string data = doc["data"].dump();
    IpcServer::GetInstance().SendMsgToClient(session, data);
    return true;
}

}; // namespace hackernel
