#include "syscall.h"
#include "file.h"
#include "process.h"
#include "util.h"
#include <net/net_namespace.h>

sys_call_ptr_t *g_sys_call_table = NULL;

int init_sys_call_table(u64 sys_call_table)
{
	if (g_sys_call_table)
		return -1;
	if (!sys_call_table)
		return -1;
	g_sys_call_table = (sys_call_ptr_t *)sys_call_table;
	return 0;
}
#if CONFIG_X86
static inline void write_cr0_forced(unsigned long val)
{
	asm volatile("mov %0,%%cr0" : : "r"(val) : "memory");
}

void enable_write_protection(void)
{
	write_cr0_forced(read_cr0() | 0x00010000);
}

void disable_write_protection(void)
{
	write_cr0_forced(read_cr0() & ~0x00010000);
}
#endif

#if CONFIG_ARM
#ifdef CONFIG_STRICT_KERNEL_RWX
struct section_perm {
	const char *name;
	unsigned long start;
	unsigned long end;
	pmdval_t mask;
	pmdval_t prot;
	pmdval_t clear;
};
static struct section_perm ro_perms[] = {
	/* Make kernel code and rodata RX (set RO). */
	{
		.name = "text/rodata RO",
		.start = (unsigned long)_stext,
		.end = (unsigned long)__init_begin,
#ifdef CONFIG_ARM_LPAE
		.mask = ~(L_PMD_SECT_RDONLY | PMD_SECT_AP2),
		.prot = L_PMD_SECT_RDONLY | PMD_SECT_AP2,
#else
		.mask = ~(PMD_SECT_APX | PMD_SECT_AP_WRITE),
		.prot = PMD_SECT_APX | PMD_SECT_AP_WRITE,
		.clear = PMD_SECT_AP_WRITE,
#endif
	},
};

static void set_kernel_text_rw(void)
{
	set_section_perms(ro_perms, ARRAY_SIZE(ro_perms), false,
			  current->active_mm);
}

static void set_kernel_text_ro(void)
{
	set_section_perms(ro_perms, ARRAY_SIZE(ro_perms), true,
			  current->active_mm);
}

void enable_write_protection(void)
{
	set_kernel_text_ro();
}

void disable_write_protection(void)
{
	set_kernel_text_rw();
}
#else
void enable_write_protection(void)
{
}

void disable_write_protection(void)
{
}
#endif

#endif
