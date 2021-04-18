#include "util.h"
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/linux/binfmts.h>

static const char __user *get_user_arg_ptr(char __user *__user *argv, int nr)
{
	const char __user *native;
	if (get_user(native, argv + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

static int count(char __user *__user *argv, int max)
{
	int i = 0;
	if (!argv) {
		return i;
	}

	for (;;) {
		const char __user *p = get_user_arg_ptr(argv, i);
		if (!p)
			break;
		++i;
	}

	return i;
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

	argc = count((char **)argv, MAX_ARG_STRINGS);
	p = kmalloc((argc + 1) * sizeof(char *), GFP_KERNEL);

	lack = copy_from_user(p, argv, argc * sizeof(char *));
	if (lack) {
		goto out;
	}

	len = 0, cursor = params;
	for (idx = 0; p[idx]; ++idx) {
		remain = size - (cursor - params);
		if (remain <= 0) {
			break;
		}
		len = strnlen_user(p[idx], remain);
		lack = copy_from_user(cursor, p[idx], len);
		if (lack) {
			break;
		}
		cursor += len;
		*(cursor - 1) = ' ';
	}
	*(cursor - 1) = '\0';
	retval = 0;
out:
	kfree(p);
	return retval;
}
