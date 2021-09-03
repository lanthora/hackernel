#include "command.h"
#include "util.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int Status = 0;

static int heartbeatHelper(int keep) {
  struct nl_msg *msg = NULL;
  pid_t tgid = getpgrp();

  Status = keep;
  do {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, FamId, 0, NLM_F_REQUEST,
                HACKERNEL_C_HANDSHAKE, HACKERNEL_FAMLY_VERSION);
    nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_TGID, tgid);
    nl_send_auto(NlSock, msg);
    nlmsg_free(msg);
    sleep(keep);
  } while (Status);

  return 0;
}

void stopHeartbeat() {
  Status = 0;
}

int handshake() {
  return heartbeatHelper(0);
}

int heartbeat() {
  return heartbeatHelper(1);
}
