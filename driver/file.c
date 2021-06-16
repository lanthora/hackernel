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
	int errcnt;
	static atomic_t atomic_errcnt = ATOMIC_INIT(0);

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
	if (!error) {
		errcnt = atomic_xchg(&atomic_errcnt, 0);
		if (unlikely(errcnt)) {
			LOG("errcnt=[%u]", errcnt);
		}
		goto out;
	}

	atomic_inc(&atomic_errcnt);

	if (error == -EAGAIN) {
		goto out;
	}

	portid = 0;
	LOG("genlmsg_unicast failed error=[%d]", error);

out:
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
	char *ptr;
	struct path path;
	int error = 0;
	int failed = 1;

	error = kern_path(filename, LOOKUP_FOLLOW, &path);
	if (!error) {
		ptr = d_path(&path, real, PATH_MAX);
		if (!IS_ERR(ptr)) {
			strcpy(real, ptr);
			failed = 0;
		}
		path_put(&path);
	}
	if (failed)
		strcpy(real, filename);

	return 0;
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

static int sys_open_helper(int dirfd, char __user *pathname, int flags,
			   struct file_perm_data *data)
{
	int is_forbidden = 0;
	char *path = NULL;
	char *real = NULL;

	path = get_absolute_path_alloc(dirfd, pathname);
	real = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path || !real)
		goto out;

	real_path_from_symlink(path, real);

	file_perm_data_fill(real, data);
	is_forbidden = protect_check_with_flags(data, flags);
	if (is_forbidden)
		goto out;

	if (!(flags & O_CREAT))
		goto out;

	if (file_exist(data)) {
		goto out;
	}

	is_forbidden = parent_write_protect_check(data);

out:
	kfree(path);
	kfree(real);
	return is_forbidden;
}

static int sys_unlink_helper(int dirfd, char __user *pathname,
			     struct file_perm_data *data)
{
	int is_forbidden = 0;
	char *path = NULL;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path)
		goto out;

	file_perm_data_fill(path, data);
	is_forbidden = unlink_protect_check(data);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(data);
	if (is_forbidden)
		goto out;

out:
	kfree(path);
	return is_forbidden;
}

static int sys_rename_helper(int srcfd, char __user *srcpath, int dstfd,
			     char __user *dstpath, struct file_perm_data *data)
{
	int is_forbidden = 0;
	char *src = NULL;
	char *dst = NULL;

	src = get_absolute_path_alloc(srcfd, srcpath);
	if (!src)
		goto out;
	file_perm_data_fill(src, data);
	is_forbidden = rename_protect_check(data);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(data);
	if (is_forbidden)
		goto out;

	dst = get_absolute_path_alloc(dstfd, dstpath);
	if (!dst)
		goto out;

	file_perm_data_fill(dst, data);
	is_forbidden = unlink_protect_check(data);
	if (is_forbidden)
		goto out;

	is_forbidden = parent_write_protect_check(data);
	if (is_forbidden)
		goto out;

out:
	kfree(src);
	kfree(dst);
	return is_forbidden;
}

asmlinkage u64 sys_open_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;
	int flags = (int)regs->si;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, pathname, flags, &data))
		return -EPERM;

	return __x64_sys_open(regs);
}

asmlinkage u64 sys_openat_hook(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;
	int flags = (int)regs->dx;

	struct file_perm_data data;

	if (sys_open_helper(dirfd, pathname, flags, &data))
		return -EPERM;

	return __x64_sys_openat(regs);
}

asmlinkage u64 sys_unlink_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	u64 error;
	struct file_perm_data data;

	if (sys_unlink_helper(AT_FDCWD, pathname, &data))
		return -EPERM;

	error = __x64_sys_unlink(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

asmlinkage u64 sys_unlinkat_hook(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;

	u64 error;
	struct file_perm_data data;

	if (sys_unlink_helper(dirfd, pathname, &data))
		return -EPERM;

	error = __x64_sys_unlinkat(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

asmlinkage u64 sys_rename_hook(struct pt_regs *regs)
{
	char *srcpath = (char *)regs->di;
	char *dstpath = (char *)regs->si;

	u64 error;
	struct file_perm_data data;

	if (sys_rename_helper(AT_FDCWD, srcpath, AT_FDCWD, dstpath, &data))
		return -EPERM;

	error = __x64_sys_rename(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

asmlinkage u64 sys_renameat_hook(struct pt_regs *regs)
{
	int srcfd = (int)regs->di;
	char *srcpath = (char *)regs->si;
	int dstfd = (int)regs->dx;
	char *dstpath = (char *)regs->r10;

	u64 error;
	struct file_perm_data data;

	if (sys_rename_helper(srcfd, srcpath, dstfd, dstpath, &data))
		return -EPERM;

	error = __x64_sys_renameat(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

asmlinkage u64 sys_renameat2_hook(struct pt_regs *regs)
{
	int srcfd = (int)regs->di;
	char *srcpath = (char *)regs->si;
	int dstfd = (int)regs->dx;
	char *dstpath = (char *)regs->r10;

	u64 error;
	struct file_perm_data data;

	if (sys_rename_helper(srcfd, srcpath, dstfd, dstpath, &data))
		return -EPERM;

	error = __x64_sys_renameat2(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

asmlinkage u64 sys_mkdir_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, pathname, O_CREAT, &data))
		return -EPERM;

	return __x64_sys_mkdir(regs);
}

asmlinkage u64 sys_mkdirat_hook(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;

	struct file_perm_data data;

	if (sys_open_helper(dirfd, pathname, O_CREAT, &data))
		return -EPERM;

	return __x64_sys_mkdirat(regs);
}

asmlinkage u64 sys_rmdir_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	u64 error;
	struct file_perm_data data;

	if (sys_unlink_helper(AT_FDCWD, pathname, &data))
		return -EPERM;

	error = __x64_sys_rmdir(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

asmlinkage u64 sys_link_hook(struct pt_regs *regs)
{
	char *dstpath = (char *)regs->si;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, dstpath, O_CREAT, &data)) {
		return -EPERM;
	}
	return __x64_sys_link(regs);
}

asmlinkage u64 sys_linkat_hook(struct pt_regs *regs)
{
	int dstfd = (int)regs->dx;
	char *dstpath = (char *)regs->r10;

	struct file_perm_data data;

	if (sys_open_helper(dstfd, dstpath, O_CREAT, &data)) {
		return -EPERM;
	}
	return __x64_sys_linkat(regs);
}

asmlinkage u64 sys_symlink_hook(struct pt_regs *regs)
{
	char *dstpath = (char *)regs->si;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, dstpath, O_CREAT, &data)) {
		return -EPERM;
	}
	return __x64_sys_symlink(regs);
}

asmlinkage u64 sys_symlinkat_hook(struct pt_regs *regs)
{
	int dstfd = (int)regs->si;
	char *dstpath = (char *)regs->dx;

	struct file_perm_data data;

	if (sys_open_helper(dstfd, dstpath, O_CREAT, &data)) {
		return -EPERM;
	}
	return __x64_sys_symlinkat(regs);
}

asmlinkage u64 sys_mknod_hook(struct pt_regs *regs)
{
	char *pathname = (char *)regs->di;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, pathname, O_CREAT, &data)) {
		return -EPERM;
	}
	return __x64_sys_mknod(regs);
}

asmlinkage u64 sys_mknodat_hook(struct pt_regs *regs)
{
	int dirfd = (int)regs->di;
	char *pathname = (char *)regs->si;

	struct file_perm_data data;

	if (sys_open_helper(dirfd, pathname, O_CREAT, &data))
		return -EPERM;

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
