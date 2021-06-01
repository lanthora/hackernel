#include "command.h"
#include "util.h"
#include <fcntl.h>
#include <stdio.h>

static int init_sys_call_table_addr(unsigned long *sys_call_table) {
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
    int error;
    struct nl_msg *msg;

    unsigned long sys_call_table;
    if (init_sys_call_table_addr(&sys_call_table)) {
        LOG("init_sys_call_table_addr failed");
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        LOG("nlmsg_alloc failed");
        return -1;
    }
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, famid, 0, NLM_F_REQUEST, HACKERNEL_C_HANDSHAKE, HACKERNEL_FAMLY_VERSION);
    error = nla_put_u64(msg, HACKERNEL_A_SCTH, sys_call_table);
    if (error) {
        LOG("nla_put_u64 failed");
        return -1;
    }

    error = nl_send_auto(nlsock, msg);
    if (error < 0) {
        LOG("nl_send_auto failed error=[%d]", error);
        return -1;
    }

    return 0;
}
