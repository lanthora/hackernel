#include "file.h"
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

// 最后一个元素必须是"",这个元素用来判断数组的结束
// 白名单和黑名单可以优化成红黑树
const char whitelist[][PATH_MIN] = { "/run", "/proc", "" };
const char blacklist[][PATH_MIN] = { "/root/test/protect/modify-me", "" };

// inode number of "/root/test/protect/modify-me"
unsigned long blackino = 7087550;

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
static int sys_open_hook(char __user *pathname, int flags, mode_t mode)
{
	int error = 0;
	char *path;
	unsigned long ino;

	path = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path) {
		goto out;
	}
	error = strncpy_from_user(path, pathname, PATH_MAX);
	if (error) {
		goto out;
	}
	ino = get_ino(path);
	printk(KERN_INFO "hackernel: open fd=[%ld] path=%s\n", ino, path);

out:
	kfree(path);
	return error;
}

static int sys_openat_hook(int dirfd, char __user *pathname, int flags,
			   mode_t mode)
{
	int error = 0;
	char *path;
	unsigned long ino, fsid;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -1;
		goto out;
	}

	ino = get_ino(path);
	if (ino == blackino && (flags & O_WRONLY)) {
		error = -1;
		goto out;
	}

	if (list_contain_top_down(whitelist, path)) {
		goto out;
	}

	// 禁止被保护的目录内创建文件
	if (list_contain_top_down(blacklist, path) && (flags & O_WRONLY)) {
		error = -1;
		goto out;
	}

	fsid = get_fsid(path);
	printk(KERN_INFO "hackernel: openat fsid=[%ld] fd=[%ld] path=[%s]\n",
	       fsid, ino, path);

out:
	kfree(path);
	return error;
}

static int sys_unlinkat_hook(int dirfd, char __user *pathname, int flags)
{
	int error = 0;
	char *path;
	unsigned long ino;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -1;
		goto out;
	}

	if (list_contain_top_down(whitelist, path)) {
		goto out;
	}

	// 禁止删除被保护文件和其父目录
	if (ino == blackino && list_contain_bottom_up(blacklist, path)) {
		error = -EPERM;
	}

	ino = get_ino(path);
	printk(KERN_INFO "hackernel: unlinkat fd=[%ld] path=%s\n", ino, path);

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
	unsigned long ino;

	src = get_absolute_path_alloc(srcfd, srcpath);
	if (!src) {
		error = -1;
		goto out;
	}
	ino = get_ino(src);
	printk(KERN_INFO "hackernel: renameat2 fd=[%ld] dst=%s\n", ino, src);
	if (ino == blackino && list_contain_bottom_up(blacklist, src)) {
		error = -EPERM;
		goto out;
	}

	dst = get_absolute_path_alloc(dstfd, dstpath);
	if (!dst) {
		error = -1;
		goto out;
	}
	ino = get_ino(dst);
	printk(KERN_INFO "hackernel: renameat2 fd=[%ld] dst=%s\n", ino, dst);

	// 禁止修改保护文件和父目录的路径
	if (ino == blackino && list_contain_bottom_up(blacklist, dst)) {
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
