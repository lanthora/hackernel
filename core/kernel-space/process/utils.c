/* SPDX-License-Identifier: GPL-2.0-only */
#include "process/utils.h"
#include <linux/slab.h>
#include <linux/uaccess.h>

static int argv_size_user(char __user *__user *argv)
{
	int argc = 0;
	char __user *cur;
	if (!argv)
		return argc;

	while (true) {
		if (get_user(cur, argv + argc))
			break;

		if (!cur)
			break;
		++argc;
	}
	return argc;
}

char *parse_argv_alloc(const char __user *const __user *argv)
{
	char *cmd;
	int argc;
	long idx, remain, len;
	unsigned long lack;
	long size = ARG_MAX;
	char __user **p = NULL, *cursor;

	cmd = kzalloc(ARG_MAX, GFP_KERNEL);
	if (!cmd)
		goto errout;

	argc = argv_size_user((char **)argv);
	if (!argc)
		goto errout;

	p = kmalloc(argc * sizeof(void *), GFP_KERNEL);

	if (!p)
		goto errout;

	lack = copy_from_user(p, argv, argc * sizeof(void *));
	if (lack)
		goto errout;

	len = 0, cursor = cmd;
	for (idx = 0; idx < argc; ++idx) {
		remain = size - (cursor - cmd);
		if (remain <= 0)
			break;

		len = strnlen_user(p[idx], remain);
		if (len == 0 || len > remain)
			goto errout;

		lack = copy_from_user(cursor, p[idx], len);
		if (lack)
			break;

		cursor += len;
		*(cursor - 1) = ' ';
	}
	if (!(cursor > cmd))
		goto errout;

	*(cursor - 1) = '\0';

	kfree(p);
	return cmd;
errout:
	kfree(p);
	kfree(cmd);
	return NULL;
}
