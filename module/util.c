#include "util.h"
#include <asm/current.h>
#include <linux/kernel.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/linux/binfmts.h>
#include <asm/uaccess.h>

static const char __user *get_user_arg_ptr(char __user * __user *argv, int nr)
{
	const char __user *native;
	if (get_user(native, argv + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

int count(char __user * __user *argv, int max)
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