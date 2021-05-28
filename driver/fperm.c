#include "fperm.h"
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

struct fperm_node {
	struct rb_node node;
	ino_t ino;
	perm_t perm;
};

struct fperm_list {
	struct list_head node;
	struct rb_root *root;
	fsid_t fsid;
};

static struct fperm_list *head;
static rwlock_t *lock;

static int fperm_node_cmp(struct fperm_node *ns, struct fperm_node *nt)
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

static int fperm_tree_insert(struct rb_root *root, struct fperm_node *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct fperm_node *this;
		int result;

		this = container_of(*new, struct fperm_node, node);
		result = fperm_node_cmp(data, this);
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

static struct fperm_node *fperm_tree_search(struct rb_root *root, ino_t ino)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct fperm_node *data;
		int result;

		data = container_of(node, struct fperm_node, node);
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

static int fperm_tree_destory(struct rb_root *root)
{
	struct fperm_node *data;

	while (!RB_EMPTY_ROOT(root)) {
		data = container_of(rb_first(root), struct fperm_node, node);
		rb_erase(&data->node, root);
		kfree(data);
	}

	kfree(root);
	return 0;
}

static int fperm_list_init(void)
{
	if (head) {
		return -EBUSY;
	}
	head = kzalloc(sizeof(struct fperm_list), GFP_KERNEL);
	if (!head) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&head->node);
	return 0;
}

static int fperm_list_add(struct fperm_list *data)
{
	list_add_tail(&data->node, &head->node);
	return 0;
}

// 查找fsid对应的权限红黑树,如果不存在就初始化红黑树
static struct rb_root *fperm_list_search(fsid_t fsid)
{
	struct fperm_list *data = NULL;

	if (!head) {
		goto err;
	}

	list_for_each_entry (data, &head->node, node) {
		if (data->fsid == fsid) {
			return data->root;
		}
	}

	data = kzalloc(sizeof(struct fperm_list), GFP_KERNEL);
	if (!data) {
		goto err;
	}

	data->fsid = fsid;
	data->root = kzalloc(sizeof(struct rb_root), GFP_KERNEL);
	if (!data->root) {
		goto err;
	}

	fperm_list_add(data);
	return data->root;

err:
	if (data) {
		kfree(data->root);
	}
	kfree(data);
	return NULL;
}

static int fperm_list_destory(void)
{
	struct fperm_list *data, *n;

	if (!head) {
		return -EPERM;
	}

	list_for_each_entry_safe (data, n, &head->node, node) {
		list_del(&data->node);
		fperm_tree_destory(data->root);
		kfree(data);
	}
	kfree(head);
	head = NULL;
	return 0;
}

int fperm_init(void)
{
	int error;
	error = fperm_list_init();
	if (error) {
		return error;
	}

	lock = kmalloc(sizeof(rwlock_t), GFP_KERNEL);
	if (!lock) {
		return -ENOMEM;
	}
	rwlock_init(lock);
	return 0;
}

int fperm_destory(void)
{
	fperm_list_destory();
	kfree(lock);
	lock = NULL;
	return 0;
}

perm_t fperm_get(const fsid_t fsid, ino_t ino)
{
	struct rb_root *root;
	struct fperm_node *node;
	perm_t retval = 0;

	read_lock(lock);

	root = fperm_list_search(fsid);
	if (!root) {
		goto out;
	}

	node = fperm_tree_search(root, ino);
	if (node) {
		retval = node->perm;
	}

out:
	read_unlock(lock);
	return retval;
}

int fperm_set(const fsid_t fsid, ino_t ino, perm_t perm)
{
	struct rb_root *root;
	struct fperm_node *node;
	int retval = 0;

	write_lock(lock);

	root = fperm_list_search(fsid);
	if (!root) {
		retval = -EAGAIN;
		goto out;
	}

	node = fperm_tree_search(root, ino);
	if (node) {
		node->perm = perm;
		goto out;
	}

	node = kzalloc(sizeof(struct fperm_node), GFP_KERNEL);
	if (!node) {
		retval = -EAGAIN;
		goto out;
	}

	node->ino = ino;
	node->perm = perm;
	fperm_tree_insert(root, node);

out:
	write_unlock(lock);
	return retval;
}
