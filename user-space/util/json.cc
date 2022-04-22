/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/json.h"
#include "hackernel/lru.h"

namespace hackernel {

namespace json {

static const size_t json_cache_size = 8;
static lru<std::string, nlohmann::json> cache(json_cache_size);

std::string dump(const nlohmann::json &doc) {
    std::string retval = doc.dump(-1, ' ', false, nlohmann::json::error_handler_t::ignore);
    DBG("json dump, %s", retval.data());
    return retval;
}

nlohmann::json parse(const std::string &msg) {
    nlohmann::json doc;
    if (!cache.get(msg, doc))
        return doc;

    // 与原本解析保持一直,允许产生异常
    doc = nlohmann::json::parse(msg);

    if (cache.put(msg, doc))
        ERR("insert json cache failed");

    return doc;
}

}; // namespace json

}; // namespace hackernel