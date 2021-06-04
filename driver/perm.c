#include "perm.h"
#include "util.h"
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

struct file_perm_node {
	struct rb_node node;
	ino_t ino;
	file_perm_t perm;
};

struct file_perm_list {
	struct list_head node;
	struct rb_root *root;
	fsid_t fsid;
};

static struct file_perm_list *file_perm_list_head;
static rwlock_t *file_perm_lock;

static int file_perm_node_cmp(struct file_perm_node *ns,
			      struct file_perm_node *nt)
{
	if (ns->ino < nt->ino) {
		return -1;
	}
	if (ns->ino > nt->ino) {
		return 1;
	}
	return 0;
}

static int ino_cmp(ino_t ns, ino_t nt)
{
	if (ns < nt) {
		return -1;
	}
	if (ns > nt) {
		return 1;
	}
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

		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {
			return -1;
		}
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

static int fperm_list_init(void)
{
	if (file_perm_list_head) {
		return -EBUSY;
	}
	file_perm_list_head =
		kzalloc(sizeof(struct file_perm_list), GFP_KERNEL);
	if (!file_perm_list_head) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&file_perm_list_head->node);
	return 0;
}

// 查找fsid对应的权限红黑树,如果不存在就初始化红黑树
static struct rb_root *fperm_list_search(fsid_t fsid)
{
	struct file_perm_list *data = NULL;

	if (!file_perm_list_head) {
		goto errout;
	}

	data = list_first_entry_or_null(&file_perm_list_head->node,
					struct file_perm_list, node);
	if (data && data->fsid == fsid) {
		return data->root;
	}

	list_for_each_entry (data, &file_perm_list_head->node, node) {
		if (data->fsid != fsid) {
			continue;
		}

		list_del(&data->node);
		list_add(&data->node, &file_perm_list_head->node);
		return data->root;
	}

	data = kzalloc(sizeof(struct file_perm_list), GFP_KERNEL);
	if (!data) {
		goto errout;
	}

	data->fsid = fsid;
	data->root = kzalloc(sizeof(struct rb_root), GFP_KERNEL);
	if (!data->root) {
		goto errout;
	}

	list_add(&data->node, &file_perm_list_head->node);
	return data->root;

errout:
	if (data) {
		kfree(data->root);
	}
	kfree(data);
	return NULL;
}

static int fperm_list_destory(void)
{
	struct file_perm_list *data, *n;

	if (!file_perm_list_head) {
		return -EPERM;
	}

	list_for_each_entry_safe (data, n, &file_perm_list_head->node, node) {
		list_del(&data->node);
		file_perm_tree_destory(data->root);
		kfree(data);
	}
	kfree(file_perm_list_head);
	file_perm_list_head = NULL;
	return 0;
}

int file_perm_init(void)
{
	int error;
	error = fperm_list_init();
	if (error) {
		return error;
	}

	file_perm_lock = kmalloc(sizeof(rwlock_t), GFP_KERNEL);
	if (!file_perm_lock) {
		return -ENOMEM;
	}
	rwlock_init(file_perm_lock);
	return 0;
}

int file_perm_destory(void)
{
	fperm_list_destory();
	kfree(file_perm_lock);
	file_perm_lock = NULL;
	return 0;
}

file_perm_t file_perm_get(const fsid_t fsid, ino_t ino)
{
	struct rb_root *root;
	struct file_perm_node *node;
	file_perm_t retval = 0;

	read_lock(file_perm_lock);

	root = fperm_list_search(fsid);
	if (!root) {
		goto out;
	}

	node = file_perm_tree_search(root, ino);
	if (node) {
		retval = node->perm;
	}

out:
	read_unlock(file_perm_lock);
	return retval;
}

int file_perm_set(const fsid_t fsid, ino_t ino, file_perm_t perm)
{
	struct rb_root *root;
	struct file_perm_node *node;
	int retval = 0;

	if (fsid == BAD_FSID || ino == BAD_INO) {
		return -EINVAL;
	}

	write_lock(file_perm_lock);

	root = fperm_list_search(fsid);
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

file_perm_t file_perm_get_path(const char *path)
{
	unsigned long fsid, ino;

	fsid = get_fsid(path);
	ino = get_ino(path);
	return file_perm_get(fsid, ino);
}

int file_perm_set_path(const char *path, file_perm_t perm)
{
	unsigned long fsid, ino;

	fsid = get_fsid(path);
	ino = get_ino(path);
	return file_perm_set(fsid, ino, perm);
}

struct process_perm_node {
	struct rb_node node;
	int seq;
	process_perm_t perm;
};
static struct rb_root *process_perm_rb_root = NULL;
static rwlock_t *process_perm_lock = NULL;

int process_perm_init(void)
{
	process_perm_rb_root = kzalloc(sizeof(struct rb_root), GFP_KERNEL);
	if (!process_perm_rb_root) {
		LOG("process_perm_rb_root init failed");
		return -ENOMEM;
	}
	process_perm_lock = kmalloc(sizeof(rwlock_t), GFP_KERNEL);
	if (!process_perm_lock) {
		return -ENOMEM;
	}
	rwlock_init(process_perm_lock);
	return 0;
}

int process_perm_destory(void)
{
	if (!process_perm_rb_root) {
		LOG("process_perm_rb_root is null");
		return -EINVAL;
	}
	kfree(process_perm_rb_root);
	process_perm_rb_root = NULL;

	kfree(process_perm_lock);
	process_perm_lock = NULL;
	return 0;
}

static int seq_cmp(int ns, int nt)
{
	if (ns < nt) {
		return -1;
	}
	if (ns > nt) {
		return 1;
	}
	return 0;
}

int precess_perm_insert(int seq)
{
	int error = 0;
	struct process_perm_node *data;
	struct rb_node **new = &(process_perm_rb_root->rb_node), *parent = NULL;

	write_lock(process_perm_lock);

	while (*new) {
		struct process_perm_node *this;
		int result;

		this = container_of(*new, struct process_perm_node, node);
		result = seq_cmp(seq, this->seq);
		parent = *new;

		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {
			error = -EEXIST;
			goto errout;
		}
	}

	data = kmalloc(sizeof(struct process_perm_node), GFP_KERNEL);
	if (!data) {
		error = -ENOMEM;
		goto errout;
	}

	data->seq = seq;
	data->perm = PROCESS_WATT;

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, process_perm_rb_root);
errout:
	write_unlock(process_perm_lock);
	return error;
}

int precess_perm_update(seq_t seq, process_perm_t status)
{
	int error = 0;
	struct process_perm_node *data;
	struct rb_node *node = process_perm_rb_root->rb_node;

	write_lock(process_perm_lock);

	while (node) {
		int result;

		data = container_of(node, struct process_perm_node, node);
		result = seq_cmp(seq, data->seq);

		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			goto found;
		}
	}

	// 没找到,返回错误码
	error = -ENOENT;
	goto errout;

found:
	// 找到了,修改状态,没有调整key,红黑树不需要调整
	data->perm = status;

errout:
	write_unlock(process_perm_lock);
	return error;
}

process_perm_t precess_perm_search(int seq)
{
	process_perm_t perm = PROCESS_INVAILD;
	struct rb_node *node = process_perm_rb_root->rb_node;

	read_lock(process_perm_lock);

	while (node) {
		struct process_perm_node *data;
		int result;

		data = container_of(node, struct process_perm_node, node);
		result = seq_cmp(seq, data->seq);

		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			perm = data->perm;
			goto out;
		}
	}

out:
	read_unlock(process_perm_lock);
	return perm;
}

int precess_perm_delele(int seq)
{
	int error = 0;
	struct rb_node *node = process_perm_rb_root->rb_node;
	struct process_perm_node *data;

	write_lock(process_perm_lock);

	while (node) {
		int result;

		data = container_of(node, struct process_perm_node, node);
		result = seq_cmp(seq, data->seq);

		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			goto found;
		}
	}
	error = ENOENT;
	goto out;
found:
	rb_erase(&data->node, process_perm_rb_root);
	kfree(data);
out:
	write_unlock(process_perm_lock);
	return error;
}
