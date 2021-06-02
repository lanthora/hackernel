#include "file.h"
#include "fperm.h"
#include "netlink.h"
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
	perm_t perm;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -EINVAL;
		goto out;
	}

	perm = fperm_get_path(path);

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
	perm = fperm_get_path(parent_path);
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
	perm_t perm;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -EINVAL;
		goto out;
	}

	perm = fperm_get_path(path);
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
	perm_t perm;

	src = get_absolute_path_alloc(srcfd, srcpath);
	if (!src) {
		error = -1;
		goto out;
	}
	perm = fperm_get_path(src);
	if (perm & RENAME_PROTECT_MASK) {
		error = -EPERM;
		goto out;
	}

	dst = get_absolute_path_alloc(dstfd, dstpath);
	if (!dst) {
		error = -1;
		goto out;
	}

	perm = fperm_get_path(dst);
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

int file_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	int code = 0;
	struct sk_buff *reply = NULL;
	void *head = NULL;
	if (!netlink_capable(skb, CAP_SYS_ADMIN)) {
		code = -EPERM;
		goto response;
	}

	if (!info->attrs[HACKERNEL_A_CODE]) {
		code = -EINVAL;
		goto response;
	}

	code = nla_get_s32(info->attrs[HACKERNEL_A_CODE]);
	switch (code) {
	case FILE_PROTECT_ENABLE: {
		code = enable_file_protect();
		goto response;
	}
	case FILE_PROTECT_DISABLE: {
		code = disable_file_protect();
		goto response;
	}
	case FILE_PROTECT_SET: {
		perm_t perm;
		char *path;
		path = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!path) {
			code = -ENOMEM;
			goto response;
		}

		if (!info->attrs[HACKERNEL_A_NAME]) {
			code = -EINVAL;
			kfree(path);
			goto response;
		}

		if (!info->attrs[HACKERNEL_A_PERM]) {
			code = -EINVAL;
			kfree(path);
			goto response;
		}
		nla_strscpy(path, info->attrs[HACKERNEL_A_NAME], PATH_MAX);
		perm = nla_get_s32(info->attrs[HACKERNEL_A_PERM]);
		code = fperm_set_path(path, perm);
		kfree(path);
		break;
	}
	default: {
		LOG("Unknown file protect command");
	}
	}

response:

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_FILE_PROTECT);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_s32(reply, HACKERNEL_A_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error)) {
		LOG("genlmsg_reply failed");
	}
	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}