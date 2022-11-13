/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/define.h"
#include "hackernel/broadcaster.h"
#include "hackernel/file.h"
#include "hackernel/ipc.h"
#include "nlc/netlink.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <nlohmann/json.hpp>

namespace hackernel {

static int update_file_protection_status(int32_t session, uint8_t status) {
    struct nl_msg *message;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_FILE_PROTECT);
    nla_put_s32(message, FILE_A_SESSION, session);
    nla_put_u8(message, FILE_A_OP_TYPE, status);
    send_free_hackernel_nlmsg(message);

    return 0;
}

int enable_file_protection(int32_t session) {
    return update_file_protection_status(session, FILE_PROTECT_ENABLE);
}

int disable_file_protection(int32_t session) {
    return update_file_protection_status(session, FILE_PROTECT_DISABLE);
}

int set_file_protection(int32_t session, const char *path, file_perm perm, int flag) {
    struct nl_msg *message;

    message = alloc_hackernel_nlmsg(HACKERNEL_C_FILE_PROTECT);
    nla_put_s32(message, FILE_A_SESSION, session);
    nla_put_u8(message, FILE_A_OP_TYPE, FILE_PROTECT_SET);
    nla_put_string(message, FILE_A_NAME, path);
    nla_put_s32(message, FILE_A_PERM, perm);
    nla_put_s32(message, FILE_A_FLAG, flag);
    send_free_hackernel_nlmsg(message);
    return 0;
}

int clear_file_protection(int32_t session) {
    return update_file_protection_status(session, FILE_PROTECT_CLEAR);
}

static int generate_file_protection_enable_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::enable";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_file_protection_disable_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::disable";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_file_protection_set_msg(const int32_t &session, const int32_t &code, unsigned long fsid,
                                            unsigned long ino, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::set";
    doc["code"] = code;
    doc["fsid"] = fsid;
    doc["ino"] = ino;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int generate_file_protection_report_msg(const char *name, file_perm perm, unsigned long fsid, unsigned long ino,
                                               std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::report";
    doc["name"] = name;
    doc["perm"] = perm;
    doc["fsid"] = fsid;
    doc["ino"] = ino;
    msg = generate_system_broadcast_msg(doc);
    return 0;
}

static int generate_file_protection_clear_msg(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::clear";
    doc["code"] = code;
    msg = generate_broadcast_msg(session, doc);
    return 0;
}

static int check_genl_file_protection_parm(struct genl_info *genl_info) {
    if (!genl_info->attrs[FILE_A_OP_TYPE]) {
        ERR("nlattr type is NULL");
        return -EINVAL;
    }

    u_int8_t type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
    switch (type) {
    case FILE_PROTECT_ENABLE:
    case FILE_PROTECT_DISABLE:
    case FILE_PROTECT_CLEAR:
        if (!genl_info->attrs[FILE_A_SESSION] || !genl_info->attrs[FILE_A_STATUS_CODE]) {
            ERR("nlattr invalid, type=[%d]", type);
            return -EINVAL;
        }
        break;
    case FILE_PROTECT_SET:
        if (!genl_info->attrs[FILE_A_FSID] || !genl_info->attrs[FILE_A_INO] || !genl_info->attrs[FILE_A_SESSION] ||
            !genl_info->attrs[FILE_A_STATUS_CODE]) {
            ERR("nlattr invalid, type=[%d]", type);
            return -EINVAL;
        }
        break;
    case FILE_PROTECT_REPORT:
        if (!genl_info->attrs[FILE_A_NAME] || !genl_info->attrs[FILE_A_PERM] || !genl_info->attrs[FILE_A_FSID] ||
            !genl_info->attrs[FILE_A_INO]) {
            ERR("nlattr invalid, type=[%d]", type);
            return -EINVAL;
        }
        break;
    default:
        ERR("Unknown process protect command Type");
        return -EINVAL;
    }
    return 0;
}

int handle_genl_file_protection(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info,
                                void *arg) {
    u_int8_t type;
    char *name;
    file_perm perm;
    int32_t session;
    int code;
    std::string msg;
    unsigned long fsid;
    unsigned long ino;

    if (check_genl_file_protection_parm(genl_info)) {
        return -EINVAL;
    }

    type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
    switch (type) {
    case FILE_PROTECT_ENABLE:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        generate_file_protection_enable_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::file::enable, session=[%d] code=[%d]", session, code);
        break;

    case FILE_PROTECT_DISABLE:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        generate_file_protection_disable_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::file::disable, session=[%d] code=[%d]", session, code);
        break;

    case FILE_PROTECT_SET:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        fsid = (unsigned long)nla_get_u64(genl_info->attrs[FILE_A_FSID]);
        ino = (unsigned long)nla_get_u64(genl_info->attrs[FILE_A_INO]);
        generate_file_protection_set_msg(session, code, fsid, ino, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::file::set, session=[%d] code=[%d]", session, code);
        break;

    case FILE_PROTECT_REPORT:
        name = nla_get_string(genl_info->attrs[FILE_A_NAME]);
        perm = nla_get_s32(genl_info->attrs[FILE_A_PERM]);
        fsid = (unsigned long)nla_get_u64(genl_info->attrs[FILE_A_FSID]);
        ino = (unsigned long)nla_get_u64(genl_info->attrs[FILE_A_INO]);
        generate_file_protection_report_msg(name, perm, fsid, ino, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::file::report, name=[%s] perm=[%d]", name, perm);
        break;

    case FILE_PROTECT_CLEAR:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        generate_file_protection_clear_msg(session, code, msg);
        broadcaster::global().broadcast(msg);
        DBG("kernel::file::clear, session=[%d] code=[%d]", session, code);
        break;
    }

    return 0;
}

}; // namespace hackernel
