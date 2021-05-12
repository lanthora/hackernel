#include "util.h"
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/linux/binfmts.h>

static int count(char __user *__user *argv, int max)
{
	int i = 0;
	int error = 0;
	char *p;
	if (!argv) {
		goto failed;
	}

	for (;;) {
		error = get_user(p, argv + i);
		if (error) {
			goto failed;
		}
		if (!p) {
			break;
		}
		++i;
	}
	return i;

failed:
	return 0;
}

int parse_pathname(const char __user *pathname, char *path, long size)
{
	unsigned long lack;
	lack = copy_from_user(path, pathname, strnlen_user(pathname, size));
	return lack;
}

int parse_argv(const char __user *const __user *argv, char *params, long size)
{
	char __user **p, *cursor;
	long idx, remain, len;
	unsigned long lack;
	int retval = -1;
	int argc;

	argc = count((char **)argv, BINPRM_BUF_SIZE);
	if (!argc) {
		goto out;
	}

	p = kmalloc(argc * sizeof(void *), GFP_KERNEL);

	if (!p) {
		goto out;
	}

	lack = copy_from_user(p, argv, argc * sizeof(void *));
	if (lack) {
		goto out;
	}

	len = 0, cursor = params;
	for (idx = 0; idx < argc; ++idx) {
		remain = size - (cursor - params);
		if (remain <= 0) {
			break;
		}

		len = strnlen_user(p[idx], remain);
		if (!len) {
			break;
		}

		lack = copy_from_user(cursor, p[idx], len);
		if (lack) {
			break;
		}

		cursor += len;
		if (cursor > params) {
			*(cursor - 1) = ' ';
		}
	}
	if (cursor > params) {
		*(cursor - 1) = '\0';
	}
	retval = 0;
out:
	kfree(p);
	return retval;
}
