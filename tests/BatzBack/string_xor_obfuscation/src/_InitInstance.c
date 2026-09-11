#include "data_globals.h"
BOOL _InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   _hInst = hInstance;

   _hWnd = CreateWindow(_szWindowClass, _szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!_hWnd)
   {
      return FALSE;
   }

   ShowWindow(_hWnd, SW_HIDE);
   UpdateWindow(_hWnd);

   return TRUE;
}
