#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

LRESULT _WndProc_16(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    volatile struct _LocalCtx {
        LRESULT result;
        PAINTSTRUCT ps;
        HDC hdc;
    } ctx;

    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        ctx.result = 0;
    }
    else if (msg == WM_PAINT) {
        ctx.hdc = BeginPaint(hWnd, &ctx.ps);
        EndPaint(hWnd, &ctx.ps);
        ctx.result = 0;
    }
    else {
        ctx.result = DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    return ctx.result;
}
#pragma optimize("", on)
