#ifndef HACKERNEL_SYSCALL
#define HACKERNEL_SYSCALL

int check_sys_call_table_addr(unsigned long *sys_call_table);
int insmod(const char *filename);
int rmmod(const char *modulename);

#endif
