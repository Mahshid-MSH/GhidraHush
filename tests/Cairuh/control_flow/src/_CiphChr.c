#include "data_globals.h"
#include <string.h>

#pragma optimize("", off)
uint32_t _CiphChr(uint32_t param_1)
{
    volatile int dummy_opaque_cond = 0;
    __asm__ volatile ("movl $1, %0" : "=m"(dummy_opaque_cond));
    if (dummy_opaque_cond) {
        const char ListA[] = "abcdefghijklmnopqrstuvwxyz";
        const char ListB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        char *Ptr;

        if ((Ptr = strchr(ListA, (int)param_1)) != NULL)
            return ListA[((Ptr - ListA) + 13) % 26];
        else if ((Ptr = strchr(ListB, (int)param_1)) != NULL)
            return ListB[((Ptr - ListB) + 13) % 26];
        else
            return param_1;
    } else {
        return 0;
    }
}
#pragma optimize("", on)
