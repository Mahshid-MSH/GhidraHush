#include "data_globals.h"
#include <string.h>
#include <stdlib.h>

uint32_t _CiphChr(uint32_t param_1)
{
    const char ListA[] = "abcdefghijklmnopqrstuvwxyz";
    const char ListB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *Ptr;

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
            // read param_1 but not modify
            volatile DWORD read_val = param_1;
            hash += read_val;
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    if ((Ptr = strchr(ListA, (int)param_1)) != NULL)
    {
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
                    check += j + (DWORD)param_1; // read param_1, not modify
                    j++;
                }
                char tmp2[32];
                memcpy(tmp2, tmp, 4);
                volatile DWORD val = (DWORD)tmp2[0] + check;
                val += len;
                free(tmp);
            }
        }
        // original return
        return ListA[((Ptr - ListA) + 13) % 26];
    }
    else if ((Ptr = strchr(ListB, (int)param_1)) != NULL)
    {
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
            // read param_1
            extra_val += (DWORD)param_1;
            memset(dummy_array, 0, sizeof(dummy_array));
        }
        // original return
        return ListB[((Ptr - ListB) + 13) % 26];
    }
    else
    {
        return param_1;
    }
}
