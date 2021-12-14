#include "hackernel/dispatcher.h"
#include "hackernel/process.h"
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
    StringSplit(std::string(doc["cmd"]), "\u001f", detal);
    std::cout << "kernel::proc::report, workdir=[" << detal[0] << "] path=[" << detal[1] << "] argv=[" << detal[2];
    for (size_t i = 3; i < detal.size(); ++i) {
        std::cout << " " << detal[i];
    }
    std::cout << "]" << std::endl;

    return true;
}

bool UserProcEnable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::proc::enable")
        return false;

    int32_t session = doc["session"].is_number_integer() ? int32_t(doc["session"]) : 0;
    ProcProtectEnable(session);
    return true;
}

bool UserProcDisable(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] != "user::proc::disable")
        return false;

    int32_t session = doc["session"].is_number_integer() ? int32_t(doc["session"]) : 0;
    ProcProtectDisable(session);
    return true;
}

}; // namespace hackernel
