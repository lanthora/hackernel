#include "syscall.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int check_sys_call_table_addr(unsigned long *sys_call_table) {
  int retval = -1;
  char line[128];
  if (sys_call_table == NULL) {
    return retval;
  }
  FILE *kallsyms = fopen("/proc/kallsyms", "r");
  if (kallsyms == NULL) {
    return retval;
  }
  while (fgets(line, sizeof(line), kallsyms)) {
    if (!strstr(line, " sys_call_table"))
      continue;
    sscanf(line, "%lx", sys_call_table);
    retval = 0;
  }
  fclose(kallsyms);
  return retval;
}