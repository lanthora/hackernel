#ifndef HACKERNEL_SYSCALL
#define HACKERNEL_SYSCALL

#include <linux/kernel.h>

typedef asmlinkage u64 (*sys_call_ptr_t)(struct pt_regs *);

extern sys_call_ptr_t *g_sys_call_table;

// 使用外部参数初始化系统调用表
int init_sys_call_table(u64 sys_call_table);

// 开关进程保护
void enable_process_protect(void);
void disable_process_protect(void);

// 开关文件保护
void enable_file_protect(void);
void disable_file_protect(void);

// 调整系统调用表的写保护状态
void disable_write_protection(void);
void enable_write_protection(void);

#endif
