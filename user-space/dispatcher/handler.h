/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DISPATCHER_HANDLER_H
#define DISPATCHER_HANDLER_H

#include <string>

namespace hackernel {

bool UserProcEnable(const std::string &msg);
bool UserProcDisable(const std::string &msg);
bool UserFileEnable(const std::string &msg);
bool UserFileDisable(const std::string &msg);
bool UserFileSet(const std::string &msg);
bool UserNetEnable(const std::string &msg);
bool UserNetDisable(const std::string &msg);
bool UserNetInsert(const std::string &msg);
bool UserNetDelete(const std::string &msg);

} // namespace hackernel

#endif
