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

static sys_call_ptr_t __x64_sys_open = NULL;
static sys_call_ptr_t __x64_sys_openat = NULL;
static sys_call_ptr_t __x64_sys_unlinkat = NULL;

// 最后一个元素必须是"",这个元素用来判断数组的结束
const char whitelist[][PATH_MIN] = { "/run", "/proc", "" };
const char blacklist[][PATH_MIN] = { "/root/test/protect/123", "" };

// 系统调用的参数与内核源码中 include/linux/syscalls.h 中的声明保持一致
static int sys_open_hook(char __user *pathname, int flags, mode_t mode)
{
	int error;
	char *filename;
	filename = kzalloc(PATH_MAX, GFP_KERNEL);
	error = strncpy_from_user(filename, pathname, PATH_MAX);
	if (error == -EFAULT) {
		goto out;
	}
	printk(KERN_INFO "hackernel: open=%s\n", filename);
	error = 0;
out:
	kfree(filename);
	return error;
}

static int list_contain(const char (*list)[PATH_MIN], const char *filename)
{
	char *item = (char *)*list;
	while (*item) {
		if (!strncmp(filename, item, strlen(item))) {
			return 1;
		}
		item += PATH_MIN;
	}
	return 0;
}

static int sys_openat_hook(int dirfd, char __user *pathname, int flags)
{
	int error = 0;
	char *path;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -1;
		goto out;
	}

	if (list_contain(whitelist, path)) {
		goto skip;
	}

	if (list_contain(blacklist, path)) {
		error = -EPERM;
		goto out;
	}

	printk(KERN_INFO "hackernel: openat: %s\n", path);
skip:
	error = 0;
out:
	kfree(path);
	return error;
}

static int sys_unlinkat_hook(int dirfd, char __user *pathname, int flags)
{
	int error = 0;
	char *path;

	path = get_absolute_path_alloc(dirfd, pathname);
	if (!path) {
		error = -1;
		goto out;
	}

	if (list_contain(whitelist, path)) {
		goto skip;
	}

	if (list_contain(blacklist, path)) {
		error = -EPERM;
		goto out;
	}

	printk(KERN_INFO "hackernel: openat: %s\n", path);
skip:
	error = 0;
out:
	kfree(path);
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

	if (sys_openat_hook(dirfd, pathname, flags)) {
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

int replace_open(void)
{
	if (!g_sys_call_table) {
		printk(KERN_ERR "hackernel: must init syscall table\n");
		return -1;
	}

	if (__x64_sys_open) {
		printk(KERN_ERR "hackernel: open doulbe init\n");
		return 0;
	}

	__x64_sys_open = g_sys_call_table[__NR_open];

	disable_write_protection();
	g_sys_call_table[__NR_open] = &sys_open_wrapper;
	enable_write_protection();
	return 0;
}

int replace_openat(void)
{
	if (!g_sys_call_table) {
		printk(KERN_ERR "hackernel: must init syscall table\n");
		return -1;
	}
	if (__x64_sys_openat) {
		printk(KERN_ERR "hackernel: open doulbe init\n");
		return 0;
	}
	__x64_sys_openat = g_sys_call_table[__NR_openat];

	disable_write_protection();
	g_sys_call_table[__NR_openat] = &sys_openat_wrapper;
	enable_write_protection();
	return 0;
}

int replace_unlinkat(void)
{
	if (!g_sys_call_table) {
		printk(KERN_ERR "hackernel: must init syscall table\n");
		return -1;
	}

	if (__x64_sys_unlinkat) {
		printk(KERN_ERR "hackernel: unlinkat doulbe init\n");
		return 0;
	}

	__x64_sys_unlinkat = g_sys_call_table[__NR_unlinkat];

	disable_write_protection();
	g_sys_call_table[__NR_unlinkat] = &sys_unlinkat_wrapper;
	enable_write_protection();
	return 0;
}

int restore_open(void)
{
	if (!g_sys_call_table) {
		return 0;
	}

	if (!__x64_sys_open) {
		return 0;
	}
	disable_write_protection();
	g_sys_call_table[__NR_open] = __x64_sys_open;
	enable_write_protection();
	__x64_sys_open = NULL;
	return 0;
}

int restore_openat(void)
{
	if (!g_sys_call_table) {
		return 0;
	}

	if (!__x64_sys_openat) {
		return 0;
	}
	disable_write_protection();
	g_sys_call_table[__NR_openat] = __x64_sys_openat;
	enable_write_protection();
	__x64_sys_openat = NULL;
	return 0;
}

int restore_unlinkat(void)
{
	if (!g_sys_call_table) {
		return 0;
	}

	if (!__x64_sys_unlinkat) {
		return 0;
	}
	disable_write_protection();
	g_sys_call_table[__NR_unlinkat] = __x64_sys_unlinkat;
	enable_write_protection();
	__x64_sys_unlinkat = NULL;
	return 0;
}
