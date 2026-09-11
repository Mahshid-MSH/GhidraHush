#include "data_globals.h"
#include <windows.h>
#include <stdio.h>      // for sprintf_s
#include <string.h>     // for memset

void FillArray(const char* param_1)
{
    int dirIndex = _dircount;
    lstrcpyA(_DirArray[dirIndex], param_1);   // <-- FIXED: removed & and multiplication
    _dircount++;

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        char local_buf[64];
        sprintf_s(local_buf, sizeof(local_buf), "Dummy: %d", si.dwNumberOfProcessors);   // <-- FIXED
        memset(local_buf, 0, sizeof(local_buf));
    }

    // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char local_buf[64];
        sprintf_s(local_buf, sizeof(local_buf), "Dummy: %d-%d-%d", st.wYear, st.wMonth, st.wDay);   // <-- FIXED
        memset(local_buf, 0, sizeof(local_buf));
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        char local_buf[64];
        sprintf_s(local_buf, sizeof(local_buf), "Dummy: %d", GetCurrentThreadId());   // <-- FIXED
        memset(local_buf, 0, sizeof(local_buf));
    }
}
