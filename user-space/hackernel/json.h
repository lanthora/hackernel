#ifndef HACKERNEL_JSON_H
#define HACKERNEL_JSON_H

#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <string>

namespace hackernel {

namespace json {

static inline std::string dump(const nlohmann::json &doc) {
    std::string retval = doc.dump(-1, ' ', false, nlohmann::json::error_handler_t::ignore);
    DBG("json dump, %s", retval.data());
    return retval;
}

}; // namespace json

}; // namespace hackernel

#endif