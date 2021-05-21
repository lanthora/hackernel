#include "util.h"
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>

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

char *get_exec_path(struct task_struct *task, void *buffer, size_t buffer_size)
{
	char *ret_ptr = NULL;
	char *tpath = buffer;
	struct vm_area_struct *vma = NULL;
	struct path base_path;

	if (NULL == tpath || NULL == task) {
		return NULL;
	}
	memset(tpath, 0, buffer_size);

	task_lock(task);

	if (task->mm && task->mm->mmap) {
		vma = task->mm->mmap;
	} else {
		task_unlock(task);
		return NULL;
	}

	while (vma) {
		if ((vma->vm_flags & VM_EXEC) && vma->vm_file) {
			base_path = vma->vm_file->f_path;
			break;
		}
		vma = vma->vm_next;
	}
	task_unlock(task);

	ret_ptr = d_path(&base_path, tpath, buffer_size);

	return ret_ptr;
}

char *get_cw_path(void *buffer, size_t buffer_size)
{
	struct path base_path;
	base_path = current->fs->pwd;
	return d_path(&base_path, buffer, buffer_size);
}