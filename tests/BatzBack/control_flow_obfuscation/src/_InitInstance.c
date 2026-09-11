#pragma optimize("", off)
#include "data_globals.h"
BOOL _InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    volatile int dummy_state = 1;
    BOOL retVal;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 0) goto end;

block1:
    _hInst = hInstance;
    _hWnd = CreateWindow(_szWindowClass, _szTitle, WS_OVERLAPPEDWINDOW,
                         CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    if (!_hWnd) {
        retVal = FALSE;
        dummy_state = 0;
        goto dummy_dispatcher;
    }
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    ShowWindow(_hWnd, SW_HIDE);
    UpdateWindow(_hWnd);
    retVal = TRUE;
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return retVal;
}
#pragma optimize("", on)
