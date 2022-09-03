/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_FILE_UTILS_H
#define HACKERNEL_FILE_UTILS_H

#include "hackernel/file.h"
#include <linux/kernel.h>

char *get_absolute_path_alloc(int dirfd, char __user *pathname);
char *get_parent_path_alloc(const char *path);
int file_id_get(const char *name, hkfsid_t *fsid, hkino_t *ino);
char *adjust_path(char *path);
int real_path_from_symlink(char *filename, char *real);

#endif
