#include "data_globals.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>      // for sprintf_s

void _FindDirectory(LPCSTR param_1)
{
    WIN32_FIND_DATAA FindData;
    HANDLE hFind;
    char Path[MAX_PATH];

    // --- ORIGINAL CODE STATEMENT ---
    hFind = FindFirstFileA(param_1, &FindData);

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        volatile int dummy_var_a = si.dwNumberOfProcessors;
        for (int i = 0; i < 10; ++i) {
            dummy_var_a += i * i;
        }
        char local_buf_1[64];
        sprintf_s(local_buf_1, sizeof(local_buf_1), "Dummy text %d", dummy_var_a);   // <-- FIXED
    }

    // --- ORIGINAL CODE STATEMENT CONTINUES ---
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    // --- SINGLE TRAVERSAL LOOP (KEPT) ---
    do {
        strcpy(Path, param_1);

        // Overwrite the trailing '*' with '\0' to get the directory path
        Path[strlen(param_1) - 1] = '\0';
        strcat(Path, FindData.cFileName);

        // FIX: correct attribute check (DIRECTORY or DIRECTORY|SYSTEM) and skip dot dirs
        if ((FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY ||
             FindData.dwFileAttributes == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) &&
            strchr(FindData.cFileName, '.') == NULL) {
            FillArray(Path);
            strcat(Path, "\\*");
            _FindDirectory(Path);
        }

    } while (FindNextFileA(hFind, &FindData) != 0);

    FindClose(hFind);

    // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        char local_buf_2[64];
        sprintf_s(local_buf_2, sizeof(local_buf_2), "Dummy text %d", dummy_tick_2);   // <-- FIXED
        SecureZeroMemory(local_buf_2, sizeof(local_buf_2));
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        volatile DWORD dummy_var_c = GetTickCount();
        for (int i = 0; i < 20; ++i) {
            dummy_var_c ^= i * i;
        }
    }
}
