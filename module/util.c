#include "util.h"
#include <linux/kernel.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/linux/binfmts.h>

int count_strings(const char *const *argv)
{
	int i;

	if (!argv)
		return 0;

	for (i = 0; argv[i]; ++i) {
		if (i >= MAX_ARG_STRINGS)
			return -E2BIG;
	}
	return i;
}