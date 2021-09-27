#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "command.h"
#include "util.h"

static int status = 0;

static int HeartbeatHelper(int keep) {
  struct nl_msg *msg = NULL;
  pid_t tgid = getpgrp();

  status = keep;
  do {
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, g_fam_id, 0, NLM_F_REQUEST,
                HACKERNEL_C_HANDSHAKE, HACKERNEL_FAMLY_VERSION);
    nla_put_s32(msg, HANDSHAKE_A_SYS_SERVICE_TGID, tgid);
    nl_send_auto(g_nl_sock, msg);
    nlmsg_free(msg);
    sleep(keep);
  } while (status);

  return 0;
}

void StopHeartbeat() { status = 0; }

int Handshake() { return HeartbeatHelper(0); }

int Heartbeat() { return HeartbeatHelper(1); }
