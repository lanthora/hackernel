#include "file.h"
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>

struct nla_policy file_policy[FILE_A_MAX + 1] = {
	[FILE_A_STATUS_CODE] = { .type = NLA_S32 },
	[FILE_A_OP_TYPE] = { .type = NLA_U8 },
	[FILE_A_NAME] = { .type = NLA_STRING },
	[FILE_A_PERM] = { .type = NLA_S32 },
};

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

static struct file_perm_list *file_perm_list_head;
static rwlock_t *file_perm_lock;

static int file_perm_node_cmp(struct file_perm_node *ns,
			      struct file_perm_node *nt)
{
	if (ns->ino < nt->ino)
		return -1;

	if (ns->ino > nt->ino)
		return 1;

	return 0;
}

static int ino_cmp(ino_t ns, ino_t nt)
{
	if (ns < nt)
		return -1;

	if (ns > nt)
		return 1;

	return 0;
}

static int file_perm_tree_insert(struct rb_root *root,
				 struct file_perm_node *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct file_perm_node *this;
		int result;

		this = container_of(*new, struct file_perm_node, node);
		result = file_perm_node_cmp(data, this);
		parent = *new;

		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return -1;
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return 0;
}

static struct file_perm_node *file_perm_tree_search(struct rb_root *root,
						    ino_t ino)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct file_perm_node *data;
		int result;

		data = container_of(node, struct file_perm_node, node);
		result = ino_cmp(ino, data->ino);

		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			return data;
		}
	}

	return NULL;
}

static int file_perm_tree_destory(struct rb_root *root)
{
	struct file_perm_node *data;

	while (!RB_EMPTY_ROOT(root)) {
		data = container_of(rb_first(root), struct file_perm_node,
				    node);
		rb_erase(&data->node, root);
		kfree(data);
	}

	kfree(root);
	return 0;
}

static int file_perm_list_init(void)
{
	if (file_perm_list_head)
		return -EPERM;

	file_perm_list_head =
		kzalloc(sizeof(struct file_perm_list), GFP_KERNEL);
	if (!file_perm_list_head)
		return -ENOMEM;

	INIT_LIST_HEAD(&file_perm_list_head->node);
	return 0;
}

// 查找fsid对应的权限红黑树,如果不存在就初始化红黑树
static struct rb_root *file_perm_list_search(fsid_t fsid)
{
	struct file_perm_list *data = NULL;

	if (!file_perm_list_head)
		goto errout;

	data = list_first_entry_or_null(&file_perm_list_head->node,
					struct file_perm_list, node);
	if (data && data->fsid == fsid)
		return data->root;

	list_for_each_entry (data, &file_perm_list_head->node, node) {
		if (data->fsid != fsid)
			continue;

		list_del(&data->node);
		list_add(&data->node, &file_perm_list_head->node);
		return data->root;
	}

	data = kzalloc(sizeof(struct file_perm_list), GFP_KERNEL);
	if (!data)
		goto errout;

	data->fsid = fsid;
	data->root = kzalloc(sizeof(struct rb_root), GFP_KERNEL);
	if (!data->root)
		goto errout;

	list_add(&data->node, &file_perm_list_head->node);
	return data->root;

errout:
	if (data)
		kfree(data->root);

	kfree(data);
	return NULL;
}

static int file_perm_list_destory(void)
{
	struct file_perm_list *data, *n;

	if (!file_perm_list_head)
		return -EPERM;

	list_for_each_entry_safe (data, n, &file_perm_list_head->node, node) {
		list_del(&data->node);
		file_perm_tree_destory(data->root);
		kfree(data);
	}
	kfree(file_perm_list_head);
	file_perm_list_head = NULL;
	return 0;
}

static file_perm_t file_perm_get(const fsid_t fsid, const ino_t ino)
{
	struct rb_root *root;
	struct file_perm_node *node;
	file_perm_t retval = 0;

	if (fsid == BAD_FSID || ino == BAD_INO)
		return INVAILD_PERM;

	read_lock(file_perm_lock);

	root = file_perm_list_search(fsid);
	if (!root)
		goto out;

	node = file_perm_tree_search(root, ino);
	if (node)
		retval = node->perm;

out:
	read_unlock(file_perm_lock);
	return retval;
}

static int file_perm_set(const fsid_t fsid, ino_t ino, file_perm_t perm)
{
	struct rb_root *root;
	struct file_perm_node *node;
	int retval = 0;

	if (fsid == BAD_FSID || ino == BAD_INO)
		return -EINVAL;

	write_lock(file_perm_lock);

	root = file_perm_list_search(fsid);
	if (!root) {
		retval = -EAGAIN;
		goto out;
	}

	node = file_perm_tree_search(root, ino);
	if (node) {
		node->perm = perm;
		goto out;
	}

	node = kzalloc(sizeof(struct file_perm_node), GFP_KERNEL);
	if (!node) {
		retval = -EAGAIN;
		goto out;
	}

	node->ino = ino;
	node->perm = perm;
	file_perm_tree_insert(root, node);

out:
	write_unlock(file_perm_lock);
	return retval;
}

int file_perm_set_path(const char *path, file_perm_t perm)
{
	unsigned long fsid, ino;
	file_id_get(path, &fsid, &ino);
	return file_perm_set(fsid, ino, perm);
}

static int file_perm_data_fill(char *path, struct file_perm_data *data)
{
	data->path = adjust_path(path);
	file_id_get(path, &data->fsid, &data->ino);
	data->this_perm = file_perm_get(data->fsid, data->ino);
	data->deny_perm = INVAILD_PERM;
	return 0;
}

static int read_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = READ_PROTECT_FLAG;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}

	return is_forbidden;
}

static int write_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = WRITE_PROTECT_FLAG;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int read_write_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = (READ_PROTECT_FLAG | WRITE_PROTECT_FLAG);
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int unlink_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = UNLINK_PROTECT_FLAG;
	int is_forbidden = data->this_perm & perm;
	if (is_forbidden) {
		data->deny_perm = perm;
		file_protect_report_to_userspace(data);
	}
	return is_forbidden;
}

static int rename_protect_check(struct file_perm_data *data)
{
	const file_perm_t perm = RENAME_PROTECT_FLAG;
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

static asmlinkage u64 sys_open_hook(struct pt_regs *regs)
{
	char *pathname = (char *)HKSC_ARGV_ONE;
	int flags = (int)HKSC_ARGV_TWO;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, pathname, flags, &data))
		return -EPERM;

	return hk_sys_open(regs);
}

static asmlinkage u64 sys_openat_hook(struct pt_regs *regs)
{
	int dirfd = (int)HKSC_ARGV_ONE;
	char *pathname = (char *)HKSC_ARGV_TWO;
	int flags = (int)HKSC_ARGV_THREE;

	struct file_perm_data data;

	if (sys_open_helper(dirfd, pathname, flags, &data))
		return -EPERM;

	return hk_sys_openat(regs);
}

static asmlinkage u64 sys_unlink_hook(struct pt_regs *regs)
{
	char *pathname = (char *)HKSC_ARGV_ONE;

	u64 error;
	struct file_perm_data data;

	if (sys_unlink_helper(AT_FDCWD, pathname, &data))
		return -EPERM;

	error = hk_sys_unlink(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

static asmlinkage u64 sys_unlinkat_hook(struct pt_regs *regs)
{
	int dirfd = (int)HKSC_ARGV_ONE;
	char *pathname = (char *)HKSC_ARGV_TWO;

	u64 error;
	struct file_perm_data data;

	if (sys_unlink_helper(dirfd, pathname, &data))
		return -EPERM;

	error = hk_sys_unlinkat(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

static asmlinkage u64 sys_rename_hook(struct pt_regs *regs)
{
	char *srcpath = (char *)HKSC_ARGV_ONE;
	char *dstpath = (char *)HKSC_ARGV_TWO;

	u64 error;
	struct file_perm_data data;

	if (sys_rename_helper(AT_FDCWD, srcpath, AT_FDCWD, dstpath, &data))
		return -EPERM;

	error = hk_sys_rename(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

static asmlinkage u64 sys_renameat_hook(struct pt_regs *regs)
{
	int srcfd = (int)HKSC_ARGV_ONE;
	char *srcpath = (char *)HKSC_ARGV_TWO;
	int dstfd = (int)HKSC_ARGV_THREE;
	char *dstpath = (char *)HKSC_ARGV_FOUR;

	u64 error;
	struct file_perm_data data;

	if (sys_rename_helper(srcfd, srcpath, dstfd, dstpath, &data))
		return -EPERM;

	error = hk_sys_renameat(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

static asmlinkage u64 sys_renameat2_hook(struct pt_regs *regs)
{
	int srcfd = (int)HKSC_ARGV_ONE;
	char *srcpath = (char *)HKSC_ARGV_TWO;
	int dstfd = (int)HKSC_ARGV_THREE;
	char *dstpath = (char *)HKSC_ARGV_FOUR;

	u64 error;
	struct file_perm_data data;

	if (sys_rename_helper(srcfd, srcpath, dstfd, dstpath, &data))
		return -EPERM;

	error = hk_sys_renameat2(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

static asmlinkage u64 sys_mkdir_hook(struct pt_regs *regs)
{
	char *pathname = (char *)HKSC_ARGV_ONE;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, pathname, O_CREAT, &data))
		return -EPERM;

	return hk_sys_mkdir(regs);
}

static asmlinkage u64 sys_mkdirat_hook(struct pt_regs *regs)
{
	int dirfd = (int)HKSC_ARGV_ONE;
	char *pathname = (char *)HKSC_ARGV_TWO;

	struct file_perm_data data;

	if (sys_open_helper(dirfd, pathname, O_CREAT, &data))
		return -EPERM;

	return hk_sys_mkdirat(regs);
}

static asmlinkage u64 sys_rmdir_hook(struct pt_regs *regs)
{
	char *pathname = (char *)HKSC_ARGV_ONE;

	u64 error;
	struct file_perm_data data;

	if (sys_unlink_helper(AT_FDCWD, pathname, &data))
		return -EPERM;

	error = hk_sys_rmdir(regs);
	if (!error && data.this_perm)
		file_perm_set(data.fsid, data.ino, INVAILD_PERM);
	return error;
}

static asmlinkage u64 sys_link_hook(struct pt_regs *regs)
{
	char *dstpath = (char *)HKSC_ARGV_TWO;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, dstpath, O_CREAT, &data))
		return -EPERM;

	return hk_sys_link(regs);
}

static asmlinkage u64 sys_linkat_hook(struct pt_regs *regs)
{
	int dstfd = (int)HKSC_ARGV_THREE;
	char *dstpath = (char *)HKSC_ARGV_FOUR;

	struct file_perm_data data;

	if (sys_open_helper(dstfd, dstpath, O_CREAT, &data))
		return -EPERM;

	return hk_sys_linkat(regs);
}

static asmlinkage u64 sys_symlink_hook(struct pt_regs *regs)
{
	char *dstpath = (char *)HKSC_ARGV_TWO;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, dstpath, O_CREAT, &data))
		return -EPERM;

	return hk_sys_symlink(regs);
}

static asmlinkage u64 sys_symlinkat_hook(struct pt_regs *regs)
{
	int dstfd = (int)HKSC_ARGV_TWO;
	char *dstpath = (char *)HKSC_ARGV_THREE;

	struct file_perm_data data;

	if (sys_open_helper(dstfd, dstpath, O_CREAT, &data))
		return -EPERM;

	return hk_sys_symlinkat(regs);
}

static asmlinkage u64 sys_mknod_hook(struct pt_regs *regs)
{
	char *pathname = (char *)HKSC_ARGV_ONE;

	struct file_perm_data data;

	if (sys_open_helper(AT_FDCWD, pathname, O_CREAT, &data))
		return -EPERM;

	return hk_sys_mknod(regs);
}

static asmlinkage u64 sys_mknodat_hook(struct pt_regs *regs)
{
	int dirfd = (int)HKSC_ARGV_ONE;
	char *pathname = (char *)HKSC_ARGV_TWO;

	struct file_perm_data data;

	if (sys_open_helper(dirfd, pathname, O_CREAT, &data))
		return -EPERM;

	return hk_sys_mknodat(regs);
}

static int file_perm_init(void)
{
	int error;
	error = file_perm_list_init();
	if (error)
		return error;

	file_perm_lock = kmalloc(sizeof(rwlock_t), GFP_KERNEL);
	if (!file_perm_lock)
		return -ENOMEM;

	rwlock_init(file_perm_lock);
	return 0;
}

static int file_perm_destory(void)
{
	file_perm_list_destory();
	if (file_perm_lock) {
		kfree(file_perm_lock);
		file_perm_lock = NULL;
	}
	return 0;
}
int enable_file_protect(void)
{
	file_perm_init();
	REG_HOOK(open);
	REG_HOOK(openat);
	REG_HOOK(unlink);
	REG_HOOK(unlinkat);
	REG_HOOK(rename);
	REG_HOOK(renameat);
	REG_HOOK(renameat2);
	REG_HOOK(mkdir);
	REG_HOOK(mkdirat);
	REG_HOOK(rmdir);
	REG_HOOK(link);
	REG_HOOK(linkat);
	REG_HOOK(symlink);
	REG_HOOK(symlinkat);
	REG_HOOK(mknod);
	REG_HOOK(mknodat);
	return 0;
}

int disable_file_protect(void)
{
	UNREG_HOOK(open);
	UNREG_HOOK(openat);
	UNREG_HOOK(unlink);
	UNREG_HOOK(unlinkat);
	UNREG_HOOK(rename);
	UNREG_HOOK(renameat);
	UNREG_HOOK(renameat2);
	UNREG_HOOK(mkdir);
	UNREG_HOOK(mkdirat);
	UNREG_HOOK(rmdir);
	UNREG_HOOK(link);
	UNREG_HOOK(linkat);
	UNREG_HOOK(symlink);
	UNREG_HOOK(symlinkat);
	UNREG_HOOK(mknod);
	UNREG_HOOK(mknodat);
	file_perm_destory();
	return 0;
}