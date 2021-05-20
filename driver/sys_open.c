#include "sys_open.h"
#include "syscall.h"
#include "util.h"
#include <asm/uaccess.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/slab.h>

static sys_call_ptr_t __x64_sys_open = NULL;
static sys_call_ptr_t __x64_sys_openat = NULL;

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

static int is_whitelist(const char *filename)
{
	// 内核日志目录，打印openat的日志会调用openat函数，所以要过滤
	if (!strncmp(filename, "/run", 4)) {
		return 1;
	}

	// vscode一直打印日志，先关掉它
	if (!strncmp(filename, "/proc", 5)) {
		return 1;
	}
	return 0;
}

static int is_relative_path(const char *filename)
{
	return strncmp(filename, "/", 1);
}

static int sys_openat_hook(int dirfd, char __user *pathname, int flags)
{
	int error;
	char *filename;
	char *abspath;
	struct file *file;

	filename = kzalloc(PATH_MAX, GFP_KERNEL);

	error = strncpy_from_user(filename, pathname, PATH_MAX);
	if (error == -EFAULT) {
		goto out;
	}

	if (is_whitelist(filename)) {
		goto skip;
	}

	if (is_relative_path(filename)) {
		printk(KERN_INFO "hackernel: is_relative_path\n");
		printk(KERN_INFO "hackernel: openat=%s\n", filename);
	} else {
		printk(KERN_INFO "hackernel: openat=%s\n", filename);
	}

skip:
	error = 0;
out:
	kfree(filename);
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
	}
	return __x64_sys_openat(regs);
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

	if (__x64_sys_openat) {
		printk(KERN_ERR "hackernel: open doulbe init\n");
		return 0;
	}

	__x64_sys_open = g_sys_call_table[__NR_open];
	__x64_sys_openat = g_sys_call_table[__NR_openat];
	disable_write_protection();
	g_sys_call_table[__NR_open] = &sys_open_wrapper;
	g_sys_call_table[__NR_openat] = &sys_openat_wrapper;
	enable_write_protection();
	return 0;
}

int restore_open(void)
{
	if (!g_sys_call_table) {
		return 0;
	}

	if (__x64_sys_open) {
		disable_write_protection();
		g_sys_call_table[__NR_open] = __x64_sys_open;
		enable_write_protection();
		__x64_sys_open = NULL;
	}

	if (__x64_sys_openat) {
		disable_write_protection();
		g_sys_call_table[__NR_openat] = __x64_sys_openat;
		enable_write_protection();
		__x64_sys_openat = NULL;
	}
	return 0;
}