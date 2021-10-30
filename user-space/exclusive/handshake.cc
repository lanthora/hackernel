#include "exclusive.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

extern int HeartbeatHelper(int interval);

int Handshake() {
    return HeartbeatHelper(0);
}
