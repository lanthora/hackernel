#ifndef HACKERNEL_JSON_H
#define HACKERNEL_JSON_H

#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

namespace json {

std::string dump(const nlohmann::json &doc);
nlohmann::json parse(const std::string &msg);

}; // namespace json

}; // namespace hackernel

#endif