#include "data_globals.h"
#include <windows.h>

void _GetVirus(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    PeekMessageA(NULL, NULL, 0, 0, PM_NOREMOVE);
    GetModuleFileNameA(NULL, _VirusPath, 260);
}
