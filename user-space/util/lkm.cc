/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/util.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int insert_kernel_module(const char *filename) {
    int error = -1;
    struct stat st;
    int fd;
    void *image;
    int image_size = 0;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        goto out;

    error = fstat(fd, &st);
    if (error)
        goto closefd;

    image_size = st.st_size;
    image = malloc(image_size);
    if (!image)
        goto closefd;

    error = read(fd, image, image_size);
    if (error < 0)
        goto freemem;

    error = syscall(__NR_init_module, image, image_size, "");
    if (error)
        goto freemem;

    error = 0;
freemem:
    free(image);
closefd:
    close(fd);
out:
    return error;
}

int remove_kernel_module(const char *module) {
    int error;
    error = syscall(__NR_delete_module, module);
    return error;
}
