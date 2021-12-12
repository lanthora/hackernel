#include "hackernel/dispatcher.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <iostream>

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
    StringSplit(std::string(doc["cmd"]), "\37", detal);
    std::cout << "kernel::proc::report, workdir=[" << detal[0] << "] path=[" << detal[1] << "] argv=[" << detal[2];
    for (int i = 3; i < detal.size(); ++i) {
        std::cout << " " << detal[i];
    }
    std::cout << "]" << std::endl;

    return true;
}

bool KernelProcStatus(const std::string &msg) {
    nlohmann::json doc = nlohmann::json::parse(msg);
    if (doc["type"] == "kernel::proc::enable") {
        std::cout << "kernel::proc::enable, ";
        std::cout << "session=[" << doc["session"] << "] ";
        std::cout << "code=[" << doc["code"] << "] ";
        std::cout << std::endl;
        return true;
    }

    if (doc["type"] == "kernel::proc::disable") {
        std::cout << "kernel::proc::disable, ";
        std::cout << "session=[" << doc["session"] << "] ";
        std::cout << "code=[" << doc["code"] << "] ";
        std::cout << std::endl;
        return true;
    }
    return false;
}
};
