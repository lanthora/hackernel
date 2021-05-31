#include "file.h"
#include "fperm.h"
#include "syscall.h"
#include "util.h"
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/slab.h>

DEFINE_HOOK(open);
DEFINE_HOOK(openat);
DEFINE_HOOK(unlinkat);
DEFINE_HOOK(renameat2);

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
static int sys_open_hook(char __user *pathname, int flags, mode_t mode)
{
	int error = 0;
	char *path;
	unsigned long fsid, ino;
	perm_t perm;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		goto out;
	}
	error = strncpy_from_user(path, pathname, PATH_MAX);
	if (error) {
		goto out;
	}
	fsid = get_fsid(path);
	ino = get_ino(path);
	perm = fperm_get(fsid, ino);

out:
	kfree(path);
	return error;
}

static int sys_openat_hook(int dirfd, char __user *pathname, int flags,
			   mode_t mode)
{
	int error = 0;
	char *path = NULL;
	char *parent_path = NULL;
	unsigned long fsid, ino;
	perm_t perm;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -EINVAL;
		goto out;
	}

	fsid = get_fsid(path);
	ino = get_ino(path);
	perm = fperm_get(fsid, ino);

	if ((flags & O_RDONLY) && (perm & READ_PROTECT_MASK)) {
		error = -EPERM;
		goto out;
	}

	if ((flags & O_WRONLY) && (perm & WRITE_PROTECT_MASK)) {
		error = -EPERM;
		goto out;
	}

	// 父目录有写保护，禁止创建文件
	if (!(flags & O_CREAT)) {
		goto out;
	}
	parent_path = get_parent_path_alloc(path);
	fsid = get_fsid(parent_path);
	ino = get_ino(parent_path);
	perm = fperm_get(fsid, ino);
	if (perm & WRITE_PROTECT_MASK) {
		error = -EPERM;
		goto out;
	}

out:
	kfree(path);
	kfree(parent_path);
	return error;
}

static int sys_unlinkat_hook(int dirfd, char __user *pathname, int flags)
{
	int error = 0;
	char *path;
	unsigned long fsid, ino;
	perm_t perm;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -EINVAL;
		goto out;
	}

	fsid = get_fsid(path);
	ino = get_ino(path);
	perm = fperm_get(fsid, ino);
	if (perm & UNLINK_PROTECT_MASK) {
		error = -EPERM;
		goto out;
	}

out:
	kfree(path);
	return error;
}

static int sys_renameat2_hook(int srcfd, char __user *srcpath, int dstfd,
			      char __user *dstpath, int flags)
{
	int error = 0;
	char *src;
	char *dst;
	unsigned long fsid, ino;
	perm_t perm;

	src = get_absolute_path_alloc(srcfd, srcpath);
	if (!src) {
		error = -1;
		goto out;
	}
	fsid = get_fsid(src);
	ino = get_ino(src);
	perm = fperm_get(fsid, ino);
	if (perm & RENAME_PROTECT_MASK) {
		error = -EPERM;
		goto out;
	}

	dst = get_absolute_path_alloc(dstfd, dstpath);
	if (!dst) {
		error = -1;
		goto out;
	}

	fsid = get_fsid(dst);
	ino = get_ino(dst);
	perm = fperm_get(fsid, ino);
	if (perm & RENAME_PROTECT_MASK) {
		error = -EPERM;
		goto out;
	}

out:
	kfree(src);
	kfree(dst);
	return error;
}

asmlinkage u64 sys_open_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	int flags = (int)regs->si;
	mode_t mode = (mode_t)regs->dx;

	if (sys_open_hook(pathname, flags, mode)) {
	}
	return __x64_sys_open(regs);
}

asmlinkage u64 sys_openat_wrapper(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;
	int flags = (int)regs->dx;
	mode_t mode = (mode_t)regs->r10;

	if (sys_openat_hook(dirfd, pathname, flags, mode)) {
		return -EPERM;
	}
	return __x64_sys_openat(regs);
}

asmlinkage u64 sys_unlinkat_wrapper(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;
	int flags = (int)regs->dx;

	if (sys_unlinkat_hook(dirfd, pathname, flags)) {
		return -EPERM;
	}
	return __x64_sys_unlinkat(regs);
}

asmlinkage u64 sys_renameat2_wrapper(struct pt_regs *regs)
{
	int srcfd = (int)regs->di;
	char *srcpath = (char *)regs->si;
	int dstfd = (int)regs->dx;
	char *dstpath = (char *)regs->r10;
	int flags = (int)regs->r8;

	if (sys_renameat2_hook(srcfd, srcpath, dstfd, dstpath, flags)) {
		return -EPERM;
	}
	return __x64_sys_renameat2(regs);
}
