#pragma optimize("", off)

#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI doweb(LPVOID param)
{
    char buffer[1024];
    SOCKET s = *((SOCKET *)param);
    volatile int ctrl_state = 1;
    DWORD retval = 0;

ctrl_dispatcher:
    if (ctrl_state == 0) goto ctrl_end;
    if (ctrl_state == 1) goto ctrl_block1;
    if (ctrl_state == 2) goto ctrl_block2;
    if (ctrl_state == 3) goto ctrl_block3;
    if (ctrl_state == 4) goto ctrl_block4;

ctrl_block1:
    // recv
    recv(s, buffer, 1024, 0);
    ctrl_state = 2;
    goto ctrl_dispatcher;

ctrl_block2:
    // send
    send(s, _mybytes, (int)_sizemybytes, 0);
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_block3:
    // closesocket
    closesocket(s);
    ctrl_state = 4;
    goto ctrl_dispatcher;

ctrl_block4:
    // return
    retval = 0;
    ctrl_state = 0;
    goto ctrl_dispatcher;

ctrl_end:
    return retval;
}

#pragma optimize("", on)
