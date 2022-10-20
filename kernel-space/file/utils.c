/* SPDX-License-Identifier: GPL-2.0-only */
#include "file/utils.h"
#include "hackernel/file.h"
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/statfs.h>

char *get_pwd_path_alloc(void)
{
	char *tmp, *buffer;
	struct path pwd;

	buffer = kzalloc(PATH_MAX, GFP_KERNEL);

	get_fs_pwd(current->fs, &pwd);
	tmp = d_path(&pwd, buffer, PATH_MAX);
	memmove(buffer, tmp, strnlen(tmp, PATH_MAX - 1) + 1);

	path_put(&pwd);

	return buffer;
}

static int get_path_prefix(int dirfd, char *prefix)
{
	struct file *file;
	char *buffer;
	char *tmp;

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

	tmp = d_path(&file->f_path, prefix, PATH_MAX);
	fput(file);

	if (IS_ERR(tmp))
		return -EINVAL;
	memmove(prefix, tmp, strnlen(tmp, PATH_MAX - 1) + 1);
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

static int is_relative_path(const char *filename)
{
	return strncmp(filename, "/", 1);
}

char *get_absolute_path_alloc(int dirfd, char __user *pathname)
{
	char *filename = NULL;
	char *path = NULL;
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

	path = adjust_path(path);
	kfree(filename);
	return path;

errout:
	kfree(path);
	kfree(filename);
	return NULL;
}

char *get_parent_path_alloc(const char *path)
{
	char *parent;
	size_t len;

	parent = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!parent)
		goto errout;

	memmove(parent, path, strnlen(path, PATH_MAX - 1) + 1);
	len = strlen(parent);
	while (len > 0 && parent[len] != '/')
		--len;

	parent[len] = '\0';

	return parent;
errout:
	kfree(parent);
	return NULL;
}

int file_id_get(const char *name, hkfsid_t *fsid, hkino_t *ino)
{
	int error;
	struct path path;
	struct kstatfs kstatfs;

	*fsid = *ino = 0;
	error = kern_path(name, LOOKUP_OPEN, &path);
	if (error)
		return -ENOENT;

	vfs_statfs(&path, &kstatfs);

	memcpy(fsid, &kstatfs.f_fsid, sizeof(hkfsid_t));
	*ino = path.dentry->d_inode->i_ino;
	path_put(&path);
	return 0;
}

int real_path_from_symlink(char *filename, char *real)
{
	char *ptr;
	struct path path;
	int error = 0;
	int failed = 1;

	error = kern_path(filename, LOOKUP_FOLLOW, &path);
	if (!error) {
		ptr = d_path(&path, real, PATH_MAX);
		if (!IS_ERR(ptr)) {
			memmove(real, ptr, strnlen(ptr, PATH_MAX - 1) + 1);
			failed = 0;
		}
		path_put(&path);
	}
	if (failed)
		strcpy(real, filename);

	return 0;
}
