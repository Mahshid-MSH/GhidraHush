#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

int APIENTRY WinMain(HINSTANCE param_1,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // Transform bool bVar1
    volatile bool bVar1_buf[2] = {{0, (bool)0}};
    volatile bool *p_bVar1 = (volatile bool *)&bVar1_buf[0];

    // Transform BOOL BVar2
    volatile BOOL BVar2_buf[2] = {{0, (BOOL)0}};
    volatile BOOL *p_BVar2 = (volatile BOOL *)&BVar2_buf[0];

    MSG local_28;

    _MyRegisterClass(param_1);
    (*p_bVar1) = _InitInstance(param_1, nCmdShow);
    if ((*p_bVar1) == 0) {
        local_28.wParam = 0;
    }
    else {
        while (((*p_BVar2) = GetMessageA(&local_28, NULL, 0, 0)) != 0) {
            TranslateMessage(&local_28);
            DispatchMessageA(&local_28);
        }
    }
    return local_28.wParam;
}
#pragma optimize("", on)
