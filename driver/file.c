#include "file.h"
#include "netlink.h"
#include "perm.h"
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
DEFINE_HOOK(unlink);
DEFINE_HOOK(unlinkat);
DEFINE_HOOK(rename);
DEFINE_HOOK(renameat);
DEFINE_HOOK(renameat2);

static int file_protect_report_to_userspace(char *filename, file_perm_t perm)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;

	if (!filename) {
		LOG("filename is null");
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if ((!skb)) {
		LOG("genlmsg_new failed");
		error = -ENOMEM;
		goto errout;
	}

	head = genlmsg_put(skb, portid, 0, &genl_family, 0,
			   HACKERNEL_C_FILE_PROTECT);
	if (!head) {
		LOG("genlmsg_put failed");
		error = -ENOMEM;
		goto errout;
	}
	error = nla_put_u8(skb, HACKERNEL_A_TYPE, FILE_PROTECT_REPORT);
	if (error) {
		LOG("nla_put_u8 failed");
		goto errout;
	}

	error = nla_put_s32(skb, HACKERNEL_A_PERM, perm);
	if (error) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_string(skb, HACKERNEL_A_NAME, filename);
	if (error) {
		LOG("nla_put_string failed");
		goto errout;
	}
	genlmsg_end(skb, head);

	error = genlmsg_unicast(&init_net, skb, portid);

	if (error == -EAGAIN) {
		goto errout;
	}

	if (error) {
		LOG("genlmsg_unicast failed error=[%d]", error);
		portid = 0;
	}
	return 0;
errout:
	nlmsg_free(skb);
	return error;
}

static int read_protect_check(char *path)
{
	const file_perm_t perm = READ_PROTECT_MASK;
	int is_forbidden = file_perm_get_path(path) & perm;
	if (is_forbidden)
		file_protect_report_to_userspace(path, perm);

	return is_forbidden;
}

static int write_protect_check(char *path)
{
	const file_perm_t perm = WRITE_PROTECT_MASK;
	int is_forbidden = file_perm_get_path(path) & perm;
	if (is_forbidden)
		file_protect_report_to_userspace(path, perm);

	return is_forbidden;
}

static int read_write_protect_check(char *path)
{
	const file_perm_t perm = (READ_PROTECT_MASK | WRITE_PROTECT_MASK);
	int is_forbidden = file_perm_get_path(path) & perm;
	if (is_forbidden)
		file_protect_report_to_userspace(path, perm);

	return is_forbidden;
}

static int unlink_protect_check(char *path)
{
	const file_perm_t perm = UNLINK_PROTECT_MASK;
	int is_forbidden = file_perm_get_path(path) & perm;
	if (is_forbidden)
		file_protect_report_to_userspace(path, perm);

	return is_forbidden;
}

static int rename_protect_check(char *path)
{
	const file_perm_t perm = RENAME_PROTECT_MASK;
	int is_forbidden = file_perm_get_path(path) & perm;
	if (is_forbidden)
		file_protect_report_to_userspace(path, perm);

	return is_forbidden;
}

static int parent_write_protect_check(char *path)
{
	int is_forbidden;
	char *parent_path = get_parent_path_alloc(path);
	is_forbidden = write_protect_check(parent_path);
	kfree(parent_path);
	return is_forbidden;
}

static int sys_openat_hook(int dirfd, char __user *pathname, int flags,
			   mode_t mode)
{
	int is_forbidden = 0;
	char *path = NULL;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path)
		goto out;

	switch (flags & READ_WRITE_MASK) {
	case O_RDONLY: {
		is_forbidden = read_protect_check(path);
		break;
	}
	case O_WRONLY: {
		is_forbidden = write_protect_check(path);
		break;
	}
	case O_RDWR: {
		is_forbidden = read_write_protect_check(path);
		break;
	}
	}

	if (!is_forbidden || (flags & O_CREAT)) {
		is_forbidden = parent_write_protect_check(path);
	}

out:
	kfree(path);
	return is_forbidden;
}

static int sys_unlinkat_hook(int dirfd, char __user *pathname, int flags)
{
	int is_forbidden = 0;
	char *path = NULL;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path)
		goto out;

	is_forbidden = unlink_protect_check(path);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(path);
	if (is_forbidden)
		goto out;
out:
	kfree(path);
	return is_forbidden;
}

static int sys_renameat2_hook(int srcfd, char __user *srcpath, int dstfd,
			      char __user *dstpath, int flags)
{
	int is_forbidden = 0;
	char *src = NULL;
	char *dst = NULL;

	src = get_absolute_path_alloc(srcfd, srcpath);
	if (!src)
		goto out;

	is_forbidden = rename_protect_check(src);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(src);
	if (is_forbidden)
		goto out;

	dst = get_absolute_path_alloc(dstfd, dstpath);
	if (!dst)
		goto out;

	is_forbidden = rename_protect_check(dst);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(dst);
	if (is_forbidden)
		goto out;

out:
	kfree(src);
	kfree(dst);
	return is_forbidden;
}

asmlinkage u64 sys_open_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	int flags = (int)regs->si;
	mode_t mode = (mode_t)regs->dx;

	if (sys_openat_hook(AT_FDCWD, pathname, flags, mode)) {
		return -EPERM;
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

asmlinkage u64 sys_unlink_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	if (sys_unlinkat_hook(AT_FDCWD, pathname, 0)) {
		return -EPERM;
	}
	return __x64_sys_unlink(regs);
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

asmlinkage u64 sys_rename_wrapper(struct pt_regs *regs)
{
	char *srcpath = (char *)regs->di;
	char *dstpath = (char *)regs->si;

	if (sys_renameat2_hook(AT_FDCWD, srcpath, AT_FDCWD, dstpath, 0)) {
		return -EPERM;
	}
	return __x64_sys_rename(regs);
}

asmlinkage u64 sys_renameat_wrapper(struct pt_regs *regs)
{
	int srcfd = (int)regs->di;
	char *srcpath = (char *)regs->si;
	int dstfd = (int)regs->dx;
	char *dstpath = (char *)regs->r10;

	if (sys_renameat2_hook(srcfd, srcpath, dstfd, dstpath, 0)) {
		return -EPERM;
	}
	return __x64_sys_renameat(regs);
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
	u8 type;
	struct sk_buff *reply = NULL;
	void *head = NULL;

	if (portid != info->snd_portid) {
		return -EPERM;
	}

	if (!info->attrs[HACKERNEL_A_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[HACKERNEL_A_TYPE]);
	switch (type) {
	case FILE_PROTECT_ENABLE: {
		code = enable_file_protect();
		goto response;
	}
	case FILE_PROTECT_DISABLE: {
		code = disable_file_protect();
		goto response;
	}
	case FILE_PROTECT_SET: {
		file_perm_t perm;
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
		code = file_perm_set_path(path, perm);
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

	error = nla_put_s32(reply, HACKERNEL_A_TYPE, type);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
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
