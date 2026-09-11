#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

int APIENTRY WinMain(HINSTANCE param_1,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    volatile int dummy_state = 1;
    bool bVar1;
    BOOL BVar2;
    MSG local_28;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 5) goto block5;
    if (dummy_state == 0) goto end;

block1:
    _MyRegisterClass(param_1);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    bVar1 = _InitInstance(param_1, nCmdShow);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    if (bVar1 == 0) {
        local_28.wParam = 0;
        dummy_state = 4;
    } else {
        dummy_state = 5;
    }
    goto dummy_dispatcher;

block4:
    // End state: return the value
    dummy_state = 0;
    goto dummy_dispatcher;

block5:
    // Loop: call GetMessageA
    BVar2 = GetMessageA(&local_28, NULL, 0, 0);
    if (BVar2 != 0) {
        TranslateMessage(&local_28);
        DispatchMessageA(&local_28);
        dummy_state = 5;  // Continue looping
    } else {
        dummy_state = 4;  // Exit loop and go to return
    }
    goto dummy_dispatcher;

end:
    return local_28.wParam;
}
#pragma optimize("", on)
