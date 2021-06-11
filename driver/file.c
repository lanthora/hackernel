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
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>

DEFINE_HOOK(open);
DEFINE_HOOK(openat);
DEFINE_HOOK(unlink);
DEFINE_HOOK(unlinkat);
DEFINE_HOOK(rename);
DEFINE_HOOK(renameat);
DEFINE_HOOK(renameat2);
DEFINE_HOOK(mkdir);
DEFINE_HOOK(mkdirat);
DEFINE_HOOK(rmdir);
DEFINE_HOOK(link);
DEFINE_HOOK(linkat);
DEFINE_HOOK(symlink);
DEFINE_HOOK(symlinkat);
DEFINE_HOOK(mknod);
DEFINE_HOOK(mknodat);

struct file_perm_data {
	char *path;
	fsid_t fsid;
	ino_t ino;
	file_perm_t this_perm;
	file_perm_t deny_perm;
};

static int file_perm_data_fill(char *path, struct file_perm_data *data)
{
	data->path = path;
	data->fsid = get_fsid(path);
	data->ino = get_ino(path);
	data->this_perm = file_perm_get(data->fsid, data->ino);
	data->deny_perm = INVAILD_PERM;
	return 0;
}

static int file_protect_report_to_userspace(struct file_perm_data *data)
{
	int error = 0;
	struct sk_buff *skb = NULL;
	void *head = NULL;
	const char *filename = data->path;
	const file_perm_t perm = data->deny_perm;

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

static int read_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = READ_PROTECT_MASK;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}

	return is_forbidden;
}

static int write_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = WRITE_PROTECT_MASK;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int read_write_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = (READ_PROTECT_MASK | WRITE_PROTECT_MASK);
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int unlink_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = UNLINK_PROTECT_MASK;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int rename_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = RENAME_PROTECT_MASK;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int parent_write_protect_check(struct file_perm_data *data)
{
	int is_forbidden;
	struct file_perm_data parent;
	char *path = get_parent_path_alloc(data->path);
	file_perm_data_fill(path, &parent);
	is_forbidden = write_protect_check(&parent);

	kfree(path);
	return is_forbidden;
}

static int file_exist(struct file_perm_data *data)
{
	return data->ino > BAD_INO;
}

static int real_path_from_symlink(char *filename, char *real)
{
	DEFINE_DELAYED_CALL(done);
	const char *link;
	struct path path;
	int error = 0;

	error = kern_path(filename, LOOKUP_OPEN, &path);
	if (error)
		goto errout;

	link = vfs_get_link(path.dentry, &done);

	// 不是符号链接
	if (IS_ERR(link)) {
		strcpy(real, filename);
		goto out;
	}

	// 相对路径的符号链
	if (link[0] != '/') {
		char *parent = get_parent_path_alloc(filename);
		strcpy(filename, parent);
		kfree(parent);
		strcat(filename, "/");
		strcat(filename, link);
		goto recursion;
	}

	// 绝对路径的符号链
	if (link[0] == '/') {
		strcpy(filename, link);
		goto recursion;
	}

recursion:
	real_path_from_symlink(filename, real);
	do_delayed_call(&done);
out:
	path_put(&path);
	return 0;
errout:
	strcpy(real, filename);
	return error;
}

static int protect_check_with_flags(struct file_perm_data *data,
				    const int flags)
{
	int is_forbidden = 0;

	switch (flags & READ_WRITE_MASK) {
	case O_RDONLY:
		is_forbidden = read_protect_check(data);
		break;

	case O_WRONLY:
		is_forbidden = write_protect_check(data);
		break;

	case O_RDWR:
		is_forbidden = read_write_protect_check(data);
		break;
	}

	return is_forbidden;
}

static int sys_openat_hook(int dirfd, char __user *pathname, int flags,
			   mode_t mode)
{
	int is_forbidden = 0;
	char *path = NULL;
	char *real = NULL;
	struct file_perm_data data;

	path = get_absolute_path_alloc(dirfd, pathname);
	real = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path || !real)
		goto out;

	real_path_from_symlink(path, real);

	file_perm_data_fill(real, &data);
	is_forbidden = protect_check_with_flags(&data, flags);
	if (is_forbidden)
		goto out;

	if (!(flags & O_CREAT))
		goto out;

	if (file_exist(&data)) {
		goto out;
	}

	is_forbidden = parent_write_protect_check(&data);

out:
	kfree(path);
	kfree(real);
	return is_forbidden;
}

static int sys_unlinkat_hook(int dirfd, char __user *pathname, int flags)
{
	int is_forbidden = 0;
	char *path = NULL;
	struct file_perm_data data;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path)
		goto out;

	file_perm_data_fill(path, &data);
	is_forbidden = unlink_protect_check(&data);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(&data);
	if (is_forbidden)
		goto out;

	if (data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);

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
	struct file_perm_data data;

	src = get_absolute_path_alloc(srcfd, srcpath);
	if (!src)
		goto out;
	file_perm_data_fill(src, &data);
	is_forbidden = rename_protect_check(&data);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(&data);
	if (is_forbidden)
		goto out;

	dst = get_absolute_path_alloc(dstfd, dstpath);
	if (!dst)
		goto out;

	file_perm_data_fill(dst, &data);
	is_forbidden = unlink_protect_check(&data);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(&data);
	if (is_forbidden)
		goto out;

	if (data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);

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

asmlinkage u64 sys_mkdir_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	mode_t mode = (mode_t)regs->dx;

	if (sys_openat_hook(AT_FDCWD, pathname, O_CREAT, mode)) {
		return -EPERM;
	}
	return __x64_sys_mkdir(regs);
}

asmlinkage u64 sys_mkdirat_wrapper(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;
	mode_t mode = (mode_t)regs->r10;

	if (sys_openat_hook(dirfd, pathname, O_CREAT, mode)) {
		return -EPERM;
	}
	return __x64_sys_mkdirat(regs);
}

asmlinkage u64 sys_rmdir_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	if (sys_unlinkat_hook(AT_FDCWD, pathname, 0)) {
		return -EPERM;
	}
	return __x64_sys_rmdir(regs);
}

asmlinkage u64 sys_link_wrapper(struct pt_regs *regs)
{
	char *dstpath = (char *)regs->si;

	if (sys_openat_hook(AT_FDCWD, dstpath, O_CREAT, 0)) {
		return -EPERM;
	}
	return __x64_sys_link(regs);
}

asmlinkage u64 sys_linkat_wrapper(struct pt_regs *regs)
{
	int dstfd = (int)regs->dx;
	char *dstpath = (char *)regs->r10;

	if (sys_openat_hook(dstfd, dstpath, O_CREAT, 0)) {
		return -EPERM;
	}
	return __x64_sys_linkat(regs);
}

asmlinkage u64 sys_symlink_wrapper(struct pt_regs *regs)
{
	char *dstpath = (char *)regs->si;

	if (sys_openat_hook(AT_FDCWD, dstpath, O_CREAT, 0)) {
		return -EPERM;
	}
	return __x64_sys_symlink(regs);
}

asmlinkage u64 sys_symlinkat_wrapper(struct pt_regs *regs)
{
	int dstfd = (int)regs->si;
	char *dstpath = (char *)regs->dx;

	if (sys_openat_hook(dstfd, dstpath, O_CREAT, 0)) {
		return -EPERM;
	}
	return __x64_sys_symlinkat(regs);
}

asmlinkage u64 sys_mknod_wrapper(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	if (sys_openat_hook(AT_FDCWD, pathname, O_CREAT, 0)) {
		return -EPERM;
	}
	return __x64_sys_mknod(regs);
}

asmlinkage u64 sys_mknodat_wrapper(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;

	if (sys_openat_hook(dirfd, pathname, O_CREAT, 0)) {
		return -EPERM;
	}
	return __x64_sys_mknodat(regs);
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
