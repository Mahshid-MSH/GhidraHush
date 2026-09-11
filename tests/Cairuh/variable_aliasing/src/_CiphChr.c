#include "data_globals.h"
#include <string.h>

#pragma optimize("", off)
uint32_t _CiphChr(uint32_t param_1)
{
    const char ListA[] = "abcdefghijklmnopqrstuvwxyz";
    const char ListB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char* volatile Ptr_buf[2] = {{NULL, (char*)0}};
    char* volatile *p_Ptr = &Ptr_buf[0];

    if (((*p_Ptr) = strchr(ListA, (int)param_1)) != NULL)
        return ListA[(((*p_Ptr) - ListA) + 13) % 26];
    else if (((*p_Ptr) = strchr(ListB, (int)param_1)) != NULL)
        return ListB[(((*p_Ptr) - ListB) + 13) % 26];
    else
        return param_1;
}
#pragma optimize("", on)
