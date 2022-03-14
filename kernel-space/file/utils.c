/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/utils.h"
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/uaccess.h>

char *get_pwd_path_alloc(void)
{
	char *tmp, *buffer;
	struct path pwd;

	buffer = kzalloc(PATH_MAX, GFP_KERNEL);

	get_fs_pwd(current->fs, &pwd);
	tmp = d_path(&pwd, buffer, PATH_MAX);
	strcpy(buffer, tmp);

	path_put(&pwd);

	return buffer;
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

/**
 * 通过这个函数获取根目录的路径,在一般情况下,根目录的路径是/
 * 但是在chroot或者使用namespace后,这个路径相应的会产生变化,
 * 目前的一个想法是:建立挂载点及对应的inode号的映射关系,并
 * 检查当前进程的根目录对应的inode号,以此获取映射关系
 */
static char *get_root_path(void *buffer, size_t buffer_size)
{
	strcpy(buffer, "/");
	return buffer;
}

static char *get_root_path_alloc(void)
{
	char *tmp, *buffer;
	buffer = kzalloc(PATH_MAX, GFP_KERNEL);
	tmp = get_root_path(buffer, PATH_MAX);
	strcpy(buffer, tmp);
	return buffer;
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

static int is_relative_path(const char *filename)
{
	return strncmp(filename, "/", 1);
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

	if (is_relative_path(filename)) {
		get_path_prefix(dirfd, path);
		strcat(path, "/");
	}
	strncat(path, filename, PATH_MAX);

	path = adjust_absolute_path(path);
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
