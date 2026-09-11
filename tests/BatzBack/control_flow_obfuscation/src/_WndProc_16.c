#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

LRESULT _WndProc_16(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    volatile int dummy_state = 1;
    LRESULT result;
    PAINTSTRUCT ps;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 0) goto end;

block1:
    if (msg == WM_DESTROY) {
        dummy_state = 2;
        goto dummy_dispatcher;
    }
    if (msg == WM_PAINT) {
        dummy_state = 3;
        goto dummy_dispatcher;
    }
    dummy_state = 4;
    goto dummy_dispatcher;

block2:
    PostQuitMessage(0);
    result = 0;
    dummy_state = 0;
    goto dummy_dispatcher;

block3:
    {
        HDC hdc = BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
        result = 0;
    }
    dummy_state = 0;
    goto dummy_dispatcher;

block4:
    result = DefWindowProcA(hWnd, msg, wParam, lParam);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return result;
}
#pragma optimize("", on)
