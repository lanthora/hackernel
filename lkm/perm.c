#include "perm.h"
#include "util.h"
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/types.h>

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

static int file_perm_list_init(void)
{
	if (file_perm_list_head) {
		return -EPERM;
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
static struct rb_root *file_perm_list_search(fsid_t fsid)
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
	error = file_perm_list_init();
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
	if (file_perm_lock) {
		kfree(file_perm_lock);
		file_perm_lock = NULL;
	}
	return 0;
}

file_perm_t file_perm_get(const fsid_t fsid, const ino_t ino)
{
	struct rb_root *root;
	struct file_perm_node *node;
	file_perm_t retval = 0;

	if (fsid == BAD_FSID || ino == BAD_INO) {
		return INVAILD_PERM;
	}

	read_lock(file_perm_lock);

	root = file_perm_list_search(fsid);
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

file_perm_t file_perm_get_path(const char *path)
{
	unsigned long fsid, ino;
	file_id_get(path, &fsid, &ino);
	return file_perm_get(fsid, ino);
}

int file_perm_set_path(const char *path, file_perm_t perm)
{
	unsigned long fsid, ino;
	file_id_get(path, &fsid, &ino);
	return file_perm_set(fsid, ino, perm);
}

// 由于id是逐一增加的,取余可以平均分配地址空间,由于散列函数的特殊实现,哈希表大小需要是2的整数次幂
#define PROCESS_PERM_MASK 0xFF
#define PROCESS_PERM_SIZE (PROCESS_PERM_MASK + 1) // 256
#define PROCESS_PERM_HASH(id) (id & (PROCESS_PERM_MASK)) // 散列函数

struct process_perm_node {
	struct hlist_node node;
	process_perm_id_t id;
	process_perm_t perm;
};

typedef struct process_perm_node process_perm_node_t;

struct process_perm_head {
	struct hlist_head head;
	rwlock_t lock;
};

typedef struct process_perm_head process_perm_head_t;

static void process_perm_head_init(process_perm_head_t *perm_head)
{
	INIT_HLIST_HEAD(&perm_head->head);
	rwlock_init(&perm_head->lock);
}

process_perm_head_t *process_perm_hlist;

int process_perm_init(void)
{
	int idx;
	const size_t size = sizeof(process_perm_head_t) * PROCESS_PERM_SIZE;
	// hlist初始化方式就是将内存中的变量设置为NULL,kzalloc可以达到相同的效果
	if (process_perm_hlist) {
		return -EPERM;
	}
	process_perm_hlist = kmalloc(size, GFP_KERNEL);
	for (idx = 0; idx < PROCESS_PERM_SIZE; ++idx) {
		process_perm_head_init(&process_perm_hlist[idx]);
	}
	return 0;
}

static void process_perm_hlist_node_destory(process_perm_head_t *perm_head)
{
	struct process_perm_node *pos;
	struct hlist_node *n;
	write_lock(&perm_head->lock);
	hlist_for_each_entry_safe (pos, n, &perm_head->head, node) {
		hlist_del(&pos->node);
		kfree(pos);
	}
	write_unlock(&perm_head->lock);
}

int process_perm_destory(void)
{
	size_t idx;
	if (!process_perm_hlist) {
		return -EPERM;
	}
	for (idx = 0; idx < PROCESS_PERM_SIZE; ++idx) {
		process_perm_hlist_node_destory(&process_perm_hlist[idx]);
	}
	kfree(process_perm_hlist);
	process_perm_hlist = NULL;
	return 0;
}

int process_perm_insert(const process_perm_id_t id)
{
	const size_t size = sizeof(process_perm_node_t);
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];
	process_perm_node_t *new = kmalloc(size, GFP_KERNEL);

	new->id = id;
	new->perm = PROCESS_WATT;

	write_lock(&perm_head->lock);
	hlist_add_head(&new->node, &perm_head->head);
	write_unlock(&perm_head->lock);
	return 0;
}

int process_perm_update(const process_perm_id_t id, const process_perm_t perm)
{
	struct process_perm_node *pos;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];

	write_lock(&perm_head->lock);
	hlist_for_each_entry (pos, &perm_head->head, node) {
		if (pos->id != id)
			continue;

		pos->perm = perm;
		break;
	}
	write_unlock(&perm_head->lock);
	return 0;
}

process_perm_t process_perm_search(const process_perm_id_t id)
{
	struct process_perm_node *pos;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];
	process_perm_t perm = PROCESS_INVAILD;

	read_lock(&perm_head->lock);
	hlist_for_each_entry (pos, &perm_head->head, node) {
		if (pos->id != id)
			continue;

		perm = pos->perm;
		break;
	}
	read_unlock(&perm_head->lock);
	return perm;
}

int process_perm_delele(const process_perm_id_t id)
{
	struct process_perm_node *victim;
	struct hlist_node *n;
	const size_t idx = PROCESS_PERM_HASH(id);
	process_perm_head_t *perm_head = &process_perm_hlist[idx];

	write_lock(&perm_head->lock);
	hlist_for_each_entry_safe (victim, n, &perm_head->head, node) {
		if (victim->id != id)
			continue;

		hlist_del(&victim->node);
		kfree(victim);
		break;
	}
	write_unlock(&perm_head->lock);
	return 0;
}