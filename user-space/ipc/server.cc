/* SPDX-License-Identifier: GPL-2.0-only */
#include "ipc/server.h"
#include "hackernel/broadcaster.h"
#include "hackernel/ipc.h"
#include "hackernel/thread.h"
#include "ipc/handler.h"
#include <algorithm>
#include <errno.h>
#include <functional>
#include <nlohmann/json.hpp>
#include <thread>
#include <unistd.h>

namespace hackernel {

using namespace ipc;

int token::update(const std::string &token) {
    static const int RESERVED_MAX = 2;

    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (token.empty()) {
        tokens_.clear();
        return 0;
    }

    tokens_.push_front(token);
    while (tokens_.size() > RESERVED_MAX)
        tokens_.pop_back();
    return 0;
}

bool token::is_vaild(const std::string &token) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const std::string &t : tokens_) {
        if (t == token)
            return true;
    }
    return false;
}

bool token::is_enabled() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return !tokens_.empty();
}

ipc_server &ipc_server::global() {
    static ipc_server instance;
    return instance;
}

int ipc_server::init() {
    clients.set_capacity(1024);

    receiver_ = std::make_shared<audience>();

    receiver_->add_msg_handler(handle_kernel_proc_report_msg);
    receiver_->add_msg_handler(handle_audit_proc_report_msg);
    receiver_->add_msg_handler(handle_kernel_file_report_msg);
    receiver_->add_msg_handler(handle_kernel_proc_enable_msg);
    receiver_->add_msg_handler(handle_kernel_proc_disable_msg);
    receiver_->add_msg_handler(handle_kernel_file_set_msg);
    receiver_->add_msg_handler(handle_kernel_file_enable_msg);
    receiver_->add_msg_handler(handle_kernel_file_disable_msg);
    receiver_->add_msg_handler(handle_kernel_net_insert_msg);
    receiver_->add_msg_handler(handle_kernel_net_delete_msg);
    receiver_->add_msg_handler(handle_kernel_net_enable_msg);
    receiver_->add_msg_handler(handle_kernel_net_disable_msg);
    receiver_->add_msg_handler(handle_user_sub_msg);
    receiver_->add_msg_handler(handle_user_unsub_msg);
    receiver_->add_msg_handler(handle_user_ctrl_exit_msg);
    receiver_->add_msg_handler(handle_user_ctrl_token_msg);
    receiver_->add_msg_handler(handle_user_test_echo_msg);

    broadcaster::global().add_audience(receiver_);
    return 0;
}

int ipc_server::start() {
    thread_manager::global().create_thread([&]() {
        change_thread_name("recevier");
        DBG("recevier enter");
        receiver_->start_consume_msg();
        DBG("recevier exit");
    });

    thread_manager::global().create_thread([&]() {
        change_thread_name("socket");
        DBG("socket enter");
        start_unix_domain_socket();
        DBG("socket exit");
    });
    return 0;
}

int ipc_server::stop() {
    running_ = false;

    if (socket_ && shutdown(socket_, SHUT_RDWR))
        DBG("close socket failed");

    if (receiver_)
        receiver_->stop_consume_msg();
    return 0;
}

int ipc_server::send_msg_to_client(const nlohmann::json &doc) {
    user_conn conn;
    session session = doc["session"];

    if (ipc_server::global().clients.get(session, conn))
        return -ESRCH;

    nlohmann::json data = doc["data"];
    data["extra"] = conn.extra;

    return send_msg_to_client(conn, json::dump(data));
}

int ipc_server::send_msg_to_client(user_conn conn, const std::string &msg) {
    socklen_t len;
    struct sockaddr *peer;
    peer = (struct sockaddr *)conn.peer.get();
    len = conn.len;
    if (sendto(socket_, msg.data(), msg.size(), 0, peer, len) == -1) {
        WARN("send error, peer=[%s], msg=[%s]", ((struct sockaddr_un *)peer)->sun_path, msg.data());
        return -EPERM;
    }
    return 0;
}

int ipc_server::handle_msg_sub(const std::string &section, const user_conn &user) {
    std::lock_guard<std::mutex> lock(sub_mutex_);
    auto cmp = [&](const user_conn_counter &item) {
        return strcmp(user.peer->sun_path, item.conn.peer->sun_path) == 0;
    };
    auto it = std::find_if(sub_[section].begin(), sub_[section].end(), cmp);
    if (it == sub_[section].end()) {
        sub_[section].emplace_back(user, 1);
    } else
        ++it->counter;
    return 0;
}

int ipc_server::handle_msg_unsub(const std::string &section, const user_conn &user) {
    std::lock_guard<std::mutex> lock(sub_mutex_);
    auto cmp = [&](const user_conn_counter &item) {
        return strcmp(user.peer->sun_path, item.conn.peer->sun_path) == 0;
    };
    auto it = std::find_if(sub_[section].begin(), sub_[section].end(), cmp);
    if (it == sub_[section].end())
        return -EPERM;
    if (--it->counter <= 0) {
        sub_[section].erase(it);
    }
    return 0;
}

int ipc_server::broadcast_msg_to_subscriber(const nlohmann::json &doc) {
    std::string section = doc["type"];
    nlohmann::json data = doc["data"];
    return broadcast_msg_to_subscriber(section, json::dump(data));
}

int ipc_server::broadcast_msg_to_subscriber(const std::string &section, const std::string &msg) {
    struct sockaddr *peer;
    socklen_t len;
    std::lock_guard<std::mutex> lock(sub_mutex_);

    for (auto it = sub_[section].begin(); it != sub_[section].end();) {
        user_conn &conn = it->conn;
        peer = (struct sockaddr *)conn.peer.get();
        len = conn.len;

        if (sendto(socket_, msg.data(), msg.size(), 0, peer, len) == -1)
            it = sub_[section].erase(it);
        else
            ++it;
    }
    return 0;
}

int ipc_server::update_token(const std::string &token) {
    token_.update(token);
    return 0;
}

int ipc_server::start_unix_domain_socket() {
    const char *SOCK_PATH = "/tmp/hackernel.sock";
    const int BUFFER_SIZE = 1024;

    char buffer[BUFFER_SIZE + 1];
    struct sockaddr_un server;

    socket_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (socket_ == -1) {
        ERR("unix domain socket create failed");
        goto errout;
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, SOCK_PATH);

    unlink(SOCK_PATH);
    if (bind(socket_, (struct sockaddr *)&server, sizeof(server)) == -1) {
        ERR("unix domain socket bind failed");
        goto errout;
    }

    socklen_t len;
    struct sockaddr_un peer;
    running_ = get_running_status();
    while (running_) {
        len = sizeof(peer);
        int size = recvfrom(socket_, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&peer, &len);

        if (size <= 0) {
            if (!size || errno == EAGAIN || errno == EINTR)
                continue;

            ERR("recvfrom errno=[%d] errmsg=[%s]", errno, strerror(errno));
            goto errout;
        }
        buffer[size] = 0;

        nlohmann::json data;
        try {
            data = json::parse(buffer);
        } catch (nlohmann::json::parse_error &ex) {
            WARN("parse error, buffer=[%s]", buffer);
            continue;
        }

        if (!data.is_object() || !data["type"].is_string()) {
            WARN("invalid request, buffer=[%s]", buffer);
            continue;
        }

        if (token_.is_enabled() && (!data["token"].is_string() || !token_.is_vaild(data["token"]))) {
            WARN("invalid token, buffer=[%s]", buffer);
            continue;
        }

        user_conn conn;
        conn.peer = std::make_shared<struct sockaddr_un>(peer);
        conn.len = len;
        conn.extra = data["extra"];
        session session = generate_user_session();
        ipc_server::global().clients.put(session, conn);

        nlohmann::json doc;
        doc["session"] = session;
        doc["type"] = std::string(data["type"]);
        doc["data"] = data;
        broadcaster::global().broadcast(json::dump(doc));
    }

    close(socket_);
    return 0;

errout:
    close(socket_);
    stop_server(HACKERNEL_UNIX_DOMAIN_SOCKET);
    return -EPERM;
}

session ipc_server::generate_user_session() {
    do {
        ++id_;
    } while (id_ == SYSTEM_SESSION);
    return id_;
}

int start_ipc_server() {
    ipc_server::global().init();
    ipc_server::global().start();
    return 0;
}

void stop_ipc_server() {
    DBG("IpcExit Exit");
    ipc_server::global().stop();
    return;
}

}; // namespace hackernel
