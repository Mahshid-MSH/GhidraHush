#include "data_globals.h"
#include <string.h>

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

uint32_t _CiphChr(uint32_t param_1)
{
    // "abcdefghijklmnopqrstuvwxyz" XOR'd with key 0x3E
    volatile char sz_ListA[] = {
        'a'^0x3E, 'b'^0x3E, 'c'^0x3E, 'd'^0x3E, 'e'^0x3E, 'f'^0x3E, 'g'^0x3E,
        'h'^0x3E, 'i'^0x3E, 'j'^0x3E, 'k'^0x3E, 'l'^0x3E, 'm'^0x3E, 'n'^0x3E,
        'o'^0x3E, 'p'^0x3E, 'q'^0x3E, 'r'^0x3E, 's'^0x3E, 't'^0x3E, 'u'^0x3E,
        'v'^0x3E, 'w'^0x3E, 'x'^0x3E, 'y'^0x3E, 'z'^0x3E, 0x00^0x3E
    };
    // "ABCDEFGHIJKLMNOPQRSTUVWXYZ" XOR'd with key 0x7A
    volatile char sz_ListB[] = {
        'A'^0x7A, 'B'^0x7A, 'C'^0x7A, 'D'^0x7A, 'E'^0x7A, 'F'^0x7A, 'G'^0x7A,
        'H'^0x7A, 'I'^0x7A, 'J'^0x7A, 'K'^0x7A, 'L'^0x7A, 'M'^0x7A, 'N'^0x7A,
        'O'^0x7A, 'P'^0x7A, 'Q'^0x7A, 'R'^0x7A, 'S'^0x7A, 'T'^0x7A, 'U'^0x7A,
        'V'^0x7A, 'W'^0x7A, 'X'^0x7A, 'Y'^0x7A, 'Z'^0x7A, 0x00^0x7A
    };

    xor_decrypt(sz_ListA, sizeof(sz_ListA), 0x3E);
    xor_decrypt(sz_ListB, sizeof(sz_ListB), 0x7A);

    char *Ptr;
    if ((Ptr = strchr((char*)sz_ListA, (int)param_1)) != NULL)
        return ((char*)sz_ListA)[((Ptr - (char*)sz_ListA) + 13) % 26];
    else if ((Ptr = strchr((char*)sz_ListB, (int)param_1)) != NULL)
        return ((char*)sz_ListB)[((Ptr - (char*)sz_ListB) + 13) % 26];
    else
        return param_1;
}
#pragma optimize("", on)
