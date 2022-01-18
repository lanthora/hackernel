/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_IPC_H
#define HACKERNEL_IPC_H

#include "broadcaster.h"
#include "hackernel/util.h"
#include <nlohmann/json.hpp>
#include <string>
#include <sys/un.h>

namespace hackernel {

typedef int32_t Session;
typedef std::shared_ptr<struct sockaddr_un> UserID;
typedef int UserIDSize;

struct UserConn {
    UserID peer;
    UserIDSize len;
    nlohmann::json extra;
};

const Session SYSTEM_SESSION = 0;

static inline std::string UserJsonWrapper(const int32_t &session, const nlohmann::json &data) {
    nlohmann::json doc;
    doc["session"] = session;
    doc["type"] = data["type"];
    doc["data"] = data;
    return doc.dump();
}

static inline std::string InternalJsonWrapper(const nlohmann::json &data) {
    return UserJsonWrapper(SYSTEM_SESSION, data);
}

int IpcWait();
void IpcExit();

}; // namespace hackernel

#endif
