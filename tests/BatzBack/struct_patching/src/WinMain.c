#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

int APIENTRY WinMain(HINSTANCE param_1,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    volatile struct _LocalCtx {
        bool bVar1;
        BOOL BVar2;
        MSG local_28;
    } ctx;

    _MyRegisterClass(param_1);
    ctx.bVar1 = _InitInstance(param_1, nCmdShow);
    if (ctx.bVar1 == 0) {
        ctx.local_28.wParam = 0;
    }
    else {
        while ((ctx.BVar2 = GetMessageA(&ctx.local_28, NULL, 0, 0)) != 0) {
            TranslateMessage(&ctx.local_28);
            DispatchMessageA(&ctx.local_28);
        }
    }
    return ctx.local_28.wParam;
}
#pragma optimize("", on)
