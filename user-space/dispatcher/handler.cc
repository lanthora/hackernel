#include "hackernel/dispatcher.h"
#include "hackernel/process.h"
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace hackernel {

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
