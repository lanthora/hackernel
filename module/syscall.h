#ifndef HACKERNEL_SYSCALL
#define HACKERNEL_SYSCALL

#include <linux/kernel.h>

typedef asmlinkage u64 (*sys_call_ptr_t)(const struct pt_regs *);

extern sys_call_ptr_t *g_sys_call_table;

// 使用外部参数初始化系统调用表
int init_sys_call_table(u64 sys_call_table);

void replace_sys_call(void);
void restore_sys_call(void);

// 无法修改cr0寄存器的值，导致无法关闭系统调用表的写保护
void disable_write_protect(void);
void enable_write_protect(void);

#endif
