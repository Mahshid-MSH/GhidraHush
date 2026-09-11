#pragma optimize("", off)
#include "data_globals.h"

void FillArray(const char* param_1)
{
    // Alias local variable dirIndex
    volatile int dirIndex_buf[2] = {{_dircount, (int)0}};
    volatile int *p_dirIndex = (volatile int *)&dirIndex_buf[0];

    lstrcpyA(&_DirArray[(*p_dirIndex) * 260], param_1);
    _dircount++;
}
#pragma optimize("", on)
