#include "util.h"
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/statfs.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/linux/binfmts.h>

static int argv_size_user(char __user *__user *argv, int max)
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
	int retval = -EFAULT;
	int argc;

	argc = argv_size_user((char **)argv, BINPRM_BUF_SIZE);
	if (!argc)
		goto out;

	p = kmalloc(argc * sizeof(void *), GFP_KERNEL);

	if (!p)
		goto out;

	lack = copy_from_user(p, argv, argc * sizeof(void *));
	if (lack)
		goto out;

	len = 0, cursor = params;
	for (idx = 1; idx < argc; ++idx) {
		remain = size - (cursor - params);
		if (remain <= 0)
			break;

		len = strnlen_user(p[idx], remain);
		if (!len)
			break;

		lack = copy_from_user(cursor, p[idx], len);
		if (lack)
			break;

		cursor += len;
		if (cursor > params)
			*(cursor - 1) = ASCII_US;
	}
	if (cursor > params)
		*(cursor - 1) = '\0';

	retval = cursor - params;
out:
	kfree(p);
	return retval;
}

char *get_exec_path(struct task_struct *task, void *buffer, size_t buffer_size)
{
	char *ret_ptr = NULL;
	char *tpath = buffer;
	struct vm_area_struct *vma = NULL;
	struct path prefix;

	if (NULL == tpath || NULL == task)
		return NULL;

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
			prefix = vma->vm_file->f_path;
			break;
		}
		vma = vma->vm_next;
	}
	task_unlock(task);

	ret_ptr = d_path(&prefix, tpath, buffer_size);

	return ret_ptr;
}

static char *get_pwd_path(void *buffer, size_t buffer_size)
{
	struct path pwd;
	get_fs_pwd(current->fs, &pwd);
	return d_path(&pwd, buffer, buffer_size);
}

#if defined(CONFIG_CHROOT)
static char *get_root_path(void *buffer, size_t buffer_size)
{
	struct path root;
	struct dentry *dentry;
	char *ptr = buffer + buffer_size - 1;
	*ptr = 0;
	get_fs_root(current->fs, &root);
	dentry = root.dentry;
	while (!IS_ROOT(dentry)) {
		ptr -= dentry->d_name.len;
		memcpy(ptr, dentry->d_name.name, dentry->d_name.len);
		*(--ptr) = '/';
		dentry = dentry->d_parent;
	}
	return ptr;
}
#else
static char *get_root_path(void *buffer, size_t buffer_size)
{
	strcpy(buffer, "/");
	return buffer;
}
#endif

char *get_root_path_alloc(void)
{
	char *tmp, *buffer;
	buffer = kzalloc(PATH_MAX, GFP_KERNEL);
	tmp = get_root_path(buffer, PATH_MAX);
	strcpy(buffer, tmp);
	return buffer;
}

char *get_pwd_path_alloc(void)
{
	char *tmp, *buffer;
	buffer = kzalloc(PATH_MAX, GFP_KERNEL);
	tmp = get_pwd_path(buffer, PATH_MAX);
	strcpy(buffer, tmp);
	return buffer;
}

char *get_current_process_path_alloc(void)
{
	char *tmp, *buffer;
	buffer = kzalloc(PATH_MAX, GFP_KERNEL);
	tmp = get_exec_path(current, buffer, PATH_MAX);
	strcpy(buffer, tmp);
	return buffer;
}

static int is_relative_path(const char *filename)
{
	return strncmp(filename, "/", 1);
}

static int get_path_prefix(int dirfd, char *prefix)
{
	struct file *file;
	char *buffer;
	char *d_path_base;

	if (!prefix)
		return -EINVAL;

	if (dirfd == AT_FDCWD) {
		buffer = get_pwd_path_alloc();
		strcat(prefix, buffer);
		kfree(buffer);
		return 0;
	}
	file = fget_raw(dirfd);
	if (!file)
		return -EINVAL;

	d_path_base = d_path(&file->f_path, prefix, PATH_MAX);
	fput(file);

	if (IS_ERR(d_path_base))
		return -EINVAL;

	if (prefix != d_path_base)
		strncpy(prefix, d_path_base, PATH_MAX);

	return 0;
}

static size_t backtrack(char *path, size_t slow)
{
	int cnt = 0;
	while (slow > 0) {
		if (path[slow] == '/')
			++cnt;

		if (cnt == 2)
			break;

		--slow;
	}
	return slow + 1;
}

static char *adjust_absolute_path(char *path)
{
	size_t slow = 0;
	size_t fast = 0;
	size_t len;
	len = strlen(path);

	while (fast < len) {
		while (1) {
			if (!strncmp(path + fast, "./", 2)) {
				fast += 2;
				continue;
			}
			if (!strncmp(path + fast, "../", 3)) {
				fast += 3;
				slow = backtrack(path, slow);
				continue;
			}
			break;
		}
		path[slow] = path[fast];
		++slow;
		++fast;
	}
	path[slow] = '\0';
	return path;
}

static char *post_adjust_absolute_path(char *path)
{
	size_t slow = 0;
	size_t fast = 0;
	size_t len;
	len = strlen(path);
	while (fast < len) {
		while (1) {
			if (!strncmp(path + fast, "//", 2)) {
				fast += 1;
				continue;
			}
			break;
		}
		path[slow] = path[fast];
		++slow;
		++fast;
	}
	if (slow >= 2 && !strncmp(path + slow - 2, "/.", 2))
		--slow;

	if (slow >= 2 && !strncmp(path + slow - 1, "/", 1))
		--slow;

	path[slow] = '\0';
	return path;
}

char *adjust_path(char *path)
{
	path = adjust_absolute_path(path);
	path = post_adjust_absolute_path(path);
	return path;
}

char *get_absolute_path_alloc(int dirfd, char __user *pathname)
{
	char *filename, *path, *retval;
	int error;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path)
		goto errout;

	filename = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!filename)
		goto errout;

	error = strncpy_from_user(filename, pathname, PATH_MAX);
	if (error == -EFAULT)
		goto errout;

	// 相对路径先获取前缀
	if (is_relative_path(filename)) {
		get_path_prefix(dirfd, path);
		strcat(path, "/");
	}
	strncat(path, filename, PATH_MAX);

	// 移除路径中的../和./
	path = adjust_absolute_path(path);
	// 移除路径中连续的//和末尾的/.
	path = post_adjust_absolute_path(path);
	retval = get_root_path_alloc();
	strcat(retval, path);

	kfree(path);
	kfree(filename);
	return retval;

errout:
	kfree(path);
	kfree(filename);
	kfree(retval);
	return NULL;
}

char *get_parent_path_alloc(const char *path)
{
	char *parent_path;
	size_t len;

	parent_path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!parent_path)
		goto errout;

	strcpy(parent_path, path);
	len = strlen(parent_path);
	while (len > 0 && parent_path[len] != '/')
		--len;

	parent_path[len] = '\0';

	return parent_path;
errout:
	kfree(parent_path);
	return NULL;
}

int file_id_get(const char *name, unsigned long *fsid, unsigned long *ino)
{
	int error;
	struct path path;
	struct kstatfs kstatfs;

	*fsid = *ino = 0;
	error = kern_path(name, LOOKUP_OPEN, &path);
	if (error)
		return -ENOENT;

	vfs_statfs(&path, &kstatfs);

	memcpy(fsid, &kstatfs.f_fsid, sizeof(unsigned long));
	*ino = path.dentry->d_inode->i_ino;
	path_put(&path);
	return 0;
}

unsigned long get_fsid(const char *name)
{
	int error;
	struct path path;
	struct kstatfs kstatfs;
	unsigned long retval;

	error = kern_path(name, LOOKUP_OPEN, &path);
	if (error)
		return 0;

	vfs_statfs(&path, &kstatfs);
	memcpy(&retval, &kstatfs.f_fsid, sizeof(unsigned long));
	path_put(&path);
	return retval;
}

unsigned long get_ino(const char *name)
{
	struct path path;
	int error;
	unsigned long retval;
	error = kern_path(name, LOOKUP_OPEN, &path);
	if (error)
		return 0;

	retval = path.dentry->d_inode->i_ino;
	path_put(&path);
	return retval;
}
