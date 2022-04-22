/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "broadcaster.h"
#include "hackernel/json.h"
#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <string>
#include <sys/un.h>

namespace hackernel {

typedef int32_t session;
typedef std::shared_ptr<struct sockaddr_un> user_id;
typedef int user_id_size;

struct user_conn {
    user_id peer;
    user_id_size len;
    nlohmann::json extra;
};

const session SYSTEM_SESSION = 0;

static inline std::string generate_broadcast_msg(const int32_t &session, const nlohmann::json &data) {
    nlohmann::json doc;
    doc["session"] = session;
    doc["type"] = data["type"];
    doc["data"] = data;
    return json::dump(doc);
}

static inline std::string generate_system_broadcast_msg(const nlohmann::json &data) {
    return generate_broadcast_msg(SYSTEM_SESSION, data);
}

int start_ipc_server();
void stop_ipc_server();

}; // namespace hackernel

#endif
