#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

LRESULT _WndProc_16(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    // Alias LRESULT result (uninitialized)
    volatile LRESULT result_buf[2] = {{0, (LRESULT)0}};
    volatile LRESULT *p_result = (volatile LRESULT *)&result_buf[0];

    PAINTSTRUCT ps;

    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        (*p_result) = 0;
    }
    else if (msg == WM_PAINT) {
        // Alias HDC hdc (initialized with BeginPaint)
        volatile HDC hdc_buf[2] = {{0, (HDC)0}};
        volatile HDC *p_hdc = (volatile HDC *)&hdc_buf[0];

        (*p_hdc) = BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
        (*p_result) = 0;
    }
    else {
        (*p_result) = DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    return (*p_result);
}
#pragma optimize("", on)
