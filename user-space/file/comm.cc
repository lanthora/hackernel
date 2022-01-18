/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/define.h"
#include "hackernel/broadcaster.h"
#include "hackernel/file.h"
#include "hackernel/ipc.h"
#include "hknl/netlink.h"
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <nlohmann/json.hpp>

namespace hackernel {

static int FileProtectStatusUpdate(int32_t session, uint8_t status) {
    struct nl_msg *message;

    message = NetlinkMsgAlloc(HACKERNEL_C_FILE_PROTECT);
    nla_put_s32(message, FILE_A_SESSION, session);
    nla_put_u8(message, FILE_A_OP_TYPE, status);
    NetlinkSend(message);

    return 0;
}

int FileProtectEnable(int32_t session) {
    return FileProtectStatusUpdate(session, FILE_PROTECT_ENABLE);
}

int FileProtectDisable(int32_t session) {
    return FileProtectStatusUpdate(session, FILE_PROTECT_DISABLE);
}

int FileProtectSet(int32_t session, const char *path, FilePerm perm) {
    struct nl_msg *message;

    message = NetlinkMsgAlloc(HACKERNEL_C_FILE_PROTECT);
    nla_put_s32(message, FILE_A_SESSION, session);
    nla_put_u8(message, FILE_A_OP_TYPE, FILE_PROTECT_SET);
    nla_put_string(message, FILE_A_NAME, path);
    nla_put_s32(message, FILE_A_PERM, perm);
    NetlinkSend(message);
    return 0;
}

static int FileEnableJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::enable";
    doc["code"] = code;
    msg = UserJsonWrapper(session, doc);
    return 0;
}

static int FileDisableJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::disable";
    doc["code"] = code;
    msg = UserJsonWrapper(session, doc);
    return 0;
}

static int FileSetJsonGen(const int32_t &session, const int32_t &code, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::set";
    doc["code"] = code;
    msg = UserJsonWrapper(session, doc);
    return 0;
}

static int FileReportJsonGen(const char *name, FilePerm perm, std::string &msg) {
    nlohmann::json doc;
    doc["type"] = "kernel::file::report";
    doc["name"] = name;
    doc["perm"] = perm;
    msg = msg = InternalJsonWrapper(doc);
    return 0;
}

int FileProtectHandler(struct nl_cache_ops *unused, struct genl_cmd *genl_cmd, struct genl_info *genl_info, void *arg) {
    u_int8_t type;
    char *name;
    FilePerm perm;
    int32_t session;
    int code;
    std::string msg;

    type = nla_get_u8(genl_info->attrs[FILE_A_OP_TYPE]);
    switch (type) {
    // TODO: 根据业务分别处理case,目前只是打印日志
    case FILE_PROTECT_ENABLE:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        FileEnableJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        DBG("kernel::file::enable, session=[%d] code=[%d]", session, code);
        break;

    case FILE_PROTECT_DISABLE:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        FileDisableJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        DBG("kernel::file::disable, session=[%d] code=[%d]", session, code);
        break;

    case FILE_PROTECT_SET:
        session = nla_get_s32(genl_info->attrs[FILE_A_SESSION]);
        code = nla_get_s32(genl_info->attrs[FILE_A_STATUS_CODE]);
        FileSetJsonGen(session, code, msg);
        Broadcaster::GetInstance().Notify(msg);
        DBG("kernel::file::set, session=[%d] code=[%d]", session, code);
        break;

    case FILE_PROTECT_REPORT:
        name = nla_get_string(genl_info->attrs[FILE_A_NAME]);
        perm = nla_get_s32(genl_info->attrs[FILE_A_PERM]);
        FileReportJsonGen(name, perm, msg);
        Broadcaster::GetInstance().Notify(msg);
        DBG("kernel::file::report, name=[%s] perm=[%d]", name, perm);
        break;

    default:
        DBG("Unknown process protect command Type");
    }

    return 0;
}

}; // namespace hackernel
