/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/syscall.h"
#include <linux/kprobes.h>
#include <linux/pgtable.h>

unsigned long *g_sys_call_table = NULL;

static struct mm_struct *init_mm_ptr = NULL;
static void init_mm_ptr_init(void)
{
	if (!hk_kallsyms_lookup_name)
		return;
	init_mm_ptr = (struct mm_struct *)hk_kallsyms_lookup_name("init_mm");
}

#if defined(CONFIG_X86)
static inline void write_cr0_forced(unsigned long val)
{
	asm volatile("mov %0,%%cr0" : : "r"(val) : "memory");
}

void enable_wp(unsigned long addr)
{
	write_cr0_forced(read_cr0() | X86_CR0_WP);
}

void disable_wp(unsigned long addr)
{
	write_cr0_forced(read_cr0() & ~X86_CR0_WP);
}
#endif

#if defined(CONFIG_ARM)

#ifdef CONFIG_ARM_LPAE
static pmdval_t mask = ~(L_PMD_SECT_RDONLY | PMD_SECT_AP2);
static pmdval_t prot = L_PMD_SECT_RDONLY | PMD_SECT_AP2;
static pmdval_t clear;
#else
static pmdval_t mask = ~(PMD_SECT_APX | PMD_SECT_AP_WRITE);
static pmdval_t prot = PMD_SECT_APX | PMD_SECT_AP_WRITE;
static pmdval_t clear = PMD_SECT_AP_WRITE;
#endif

static inline void section_update(unsigned long addr, pmdval_t mask,
				  pmdval_t prot, struct mm_struct *mm)
{
	pmd_t *pmd;

	pmd = pmd_offset(
		pud_offset(p4d_offset(pgd_offset(mm, addr), addr), addr), addr);
	pmd[0] = __pmd((pmd_val(pmd[0]) & mask) | prot);

	flush_pmd_entry(pmd);
	local_flush_tlb_kernel_range(addr, addr + SECTION_SIZE);
}

void enable_wp(unsigned long addr)
{
	section_update(addr & SECTION_MASK, mask, prot, init_mm_ptr);
}

void disable_wp(unsigned long addr)
{
	section_update(addr & SECTION_MASK, mask, clear, init_mm_ptr);
}
#endif

#if defined(CONFIG_ARM64)

static int get_kern_addr_ptep(unsigned long addr, pte_t **ptepp)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

	addr = arch_kasan_reset_tag(addr);
	if ((((long)addr) >> VA_BITS) != -1UL)
		return 0;

	pgdp = (init_mm_ptr->pgd +
		(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1)));
	if (pgd_none(READ_ONCE(*pgdp)))
		return 0;

	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(READ_ONCE(*p4dp)))
		return 0;

	pudp = pud_offset(p4dp, addr);
	pud = READ_ONCE(*pudp);
	if (pud_none(pud))
		return 0;

	if (pud_sect(pud))
		return pfn_valid(pud_pfn(pud));

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (pmd_none(pmd))
		return 0;

	if (pmd_sect(pmd))
		return pfn_valid(pmd_pfn(pmd));

	ptep = pte_offset_kernel(pmdp, addr);
	*ptepp = ptep;
	pte = *ptep;
	if (pte_none(pte))
		return 0;

	return pfn_valid(pte_pfn(pte));
}

void enable_wp(unsigned long addr)
{
	pte_t *ptep;
	if (!get_kern_addr_ptep(addr, &ptep))
		return;
	set_pte(ptep, pte_wrprotect(*ptep));
	flush_tlb_all();
}

void disable_wp(unsigned long addr)
{
	pte_t *ptep;
	if (!get_kern_addr_ptep(addr, &ptep))
		return;
	set_pte(ptep, pte_mkwrite(*ptep));
	flush_tlb_all();
}
#endif

kallsyms_lookup_name_t hk_kallsyms_lookup_name = NULL;
static struct kprobe hk_kp = { .symbol_name = "kallsyms_lookup_name" };
static void hk_kallsyms_lookup_name_init(void)
{
	if (register_kprobe(&hk_kp)) {
		ERR("please set CONFIG_KALLSYMS_ALL=y");
		goto out;
	}
	hk_kallsyms_lookup_name = (kallsyms_lookup_name_t)hk_kp.addr;
out:
	unregister_kprobe(&hk_kp);
}

static int sys_call_table_init(void)
{
	unsigned long syscall_kernel;
	if (!hk_kallsyms_lookup_name)
		return -EPERM;

	syscall_kernel = hk_kallsyms_lookup_name("sys_call_table");
	g_sys_call_table = (unsigned long *)syscall_kernel;
	return 0;
}

void syscall_early_init(void)
{
	hk_kallsyms_lookup_name_init();
	init_mm_ptr_init();
	sys_call_table_init();
}
