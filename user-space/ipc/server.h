/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IPC_SERVER_H
#define IPC_SERVER_H

#include "hackernel/ipc.h"
#include "hackernel/lru.h"
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sys/socket.h>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace hackernel {

namespace ipc {

typedef lru<session, user_conn> conn_cache;

struct user_conn_counter {
    user_conn conn;
    int counter;
};

class token {
public:
    int update(const std::string &token);
    bool is_vaild(const std::string &token);
    bool is_enabled();

private:
    std::shared_mutex mutex_;
    std::list<std::string> tokens_;
};

class ipc_server {
public:
    static ipc_server &global();
    conn_cache clients;

    int init();
    int start();
    int stop();

    int handle_msg_sub(const std::string &section, const user_conn &user);
    int handle_msg_unsub(const std::string &section, const user_conn &user);
    int send_msg_to_client(const nlohmann::json &doc);
    int broadcast_msg_to_subscriber(const nlohmann::json &doc);

    int update_token(const std::string &token);

private:
    int send_msg_to_client(user_conn conn, const std::string &msg);
    int broadcast_msg_to_subscriber(const std::string &section, const std::string &msg);

private:
    std::shared_ptr<audience> audience_ = nullptr;
    bool running_;
    int socket_ = 0;
    std::map<std::string, std::list<user_conn_counter>> sub_;
    std::mutex sub_mutex_;
    std::atomic<session> id_ = SYSTEM_SESSION;
    token token_;

private:
    int start_unix_domain_socket();
    session generate_user_session();
    bool check_token(const nlohmann::json &data);
};

}; // namespace ipc

}; // namespace hackernel

#endif
