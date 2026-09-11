#include "data_globals.h"
#include <windows.h>

LRESULT _WndProc_16(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LRESULT result;
    PAINTSTRUCT ps;  // added

    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        result = 0;
    }
    else if (msg == WM_PAINT) {
        HDC hdc = BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
        result = 0;
    }
    else {
        result = DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    return result;
}
