#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int APIENTRY WinMain(HINSTANCE param_1,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    bool bVar1;
    BOOL BVar2;
    MSG local_28;

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
        volatile int readLocal = local_28.wParam;
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    _MyRegisterClass(param_1);
    bVar1 = _InitInstance(param_1, nCmdShow);
    if (bVar1 == 0) {
        local_28.wParam = 0;
    }
    else {
        while ((BVar2 = GetMessageA(&local_28, NULL, 0, 0)) != 0) {
            TranslateMessage(&local_28);
            DispatchMessageA(&local_28);

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
                volatile int readLocal3 = BVar2;
                SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
                SYSTEM_INFO si2;
                GetSystemInfo(&si2);
                volatile DWORD dummyProc = si2.dwNumberOfProcessors;
            }
        }
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
                volatile int readLocal2 = local_28.wParam;
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    return local_28.wParam;
}
