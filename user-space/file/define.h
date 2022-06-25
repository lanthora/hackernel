/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_FILE_DEFINE_H
#define HACKERNEL_FILE_DEFINE_H

#include "hackernel/util.h"

EXTERN_C_BEGIN

enum {
    FILE_A_UNSPEC,
    FILE_A_SESSION,

    FILE_A_STATUS_CODE,
    FILE_A_OP_TYPE,
    FILE_A_NAME,
    FILE_A_PERM,
    FILE_A_FLAG,
    FILE_A_FSID,
    FILE_A_INO,
    __FILE_A_MAX,
};
#define FILE_A_MAX (__FILE_A_MAX - 1)

EXTERN_C_END

#endif
