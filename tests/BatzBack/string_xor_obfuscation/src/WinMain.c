#include "data_globals.h"
#include <windows.h>

int APIENTRY WinMain(HINSTANCE param_1,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    bool bVar1;
    BOOL BVar2;
    MSG local_28;

    _MyRegisterClass(param_1);
    bVar1 = _InitInstance(param_1, nCmdShow);
    if (bVar1 == 0) {
        local_28.wParam = 0;
    }
    else {
        while ((BVar2 = GetMessageA(&local_28, NULL, 0, 0)) != 0) {
            TranslateMessage(&local_28);
            DispatchMessageA(&local_28);
        }
    }
    return local_28.wParam;
}

