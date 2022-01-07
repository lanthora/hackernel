/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IPC_HANDLER_H
#define IPC_HANDLER_H

#include <string>

namespace hackernel {

bool UserMsgSub(const std::string &msg);
bool UserMsgUnsub(const std::string &msg);
bool UserCtrlExit(const std::string &msg);
bool UserCtrlToken(const std::string &msg);

bool KernelProcReport(const std::string &msg);
bool KernelProcEnable(const std::string &msg);
bool KernelProcDisable(const std::string &msg);

bool KernelFileReport(const std::string &msg);
bool KernelFileSet(const std::string &msg);
bool KernelFileEnable(const std::string &msg);
bool KernelFileDisable(const std::string &msg);

bool KernelNetInsert(const std::string &msg);
bool KernelNetDelete(const std::string &msg);
bool KernelNetEnable(const std::string &msg);
bool KernelNetDisable(const std::string &msg);

bool AuditProcReport(const std::string &msg);

}; // namespace hackernel

#endif
