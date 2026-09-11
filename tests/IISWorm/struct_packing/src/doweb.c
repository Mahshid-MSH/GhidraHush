#pragma optimize("", off)

#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI doweb(LPVOID param)
{
    volatile struct _LocalCtx {
        char buffer[1024];
        SOCKET s;
    } ctx;

    ctx.s = *((SOCKET *)param);

    recv(ctx.s, ctx.buffer, 1024, 0);
    send(ctx.s, _mybytes, (int)_sizemybytes, 0);
    closesocket(ctx.s);

    return 0;
}

#pragma optimize("", on)
