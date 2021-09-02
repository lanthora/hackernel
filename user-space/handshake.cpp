#include "command.h"
#include "util.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int initSyscallTableAddr(unsigned long *sys_call_table) {
  int retval = -1;
  char line[128];

  if (sys_call_table == NULL) {
    return retval;
  }

  *sys_call_table = 0UL;

  FILE *kallsyms = fopen("/proc/kallsyms", "r");
  if (kallsyms == NULL) {
    return retval;
  }

  while (fgets(line, sizeof(line), kallsyms)) {
    if (!strstr(line, " sys_call_table"))
      continue;
    sscanf(line, "%lx", sys_call_table);
  }

  fclose(kallsyms);
  return !*sys_call_table;
}

int handshake() {
  struct nl_msg *msg = NULL;

  unsigned long sys_call_table;
  initSyscallTableAddr(&sys_call_table);

  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
              HACKERNEL_C_HANDSHAKE, HACKERNEL_FAMLY_VERSION);
  nla_put_u64(msg, HANDSHAKE_A_SYS_CALL_TABLE_HEADER, sys_call_table);
  nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_PID, getpid());
  nl_send_auto(NlSock, msg);
  nlmsg_free(msg);
  return 0;
}
