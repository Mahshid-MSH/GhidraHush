#include "data_globals.h"
#include <windows.h>

void FillArray(const char* param_1)
{
    int dirIndex = _dircount;
    lstrcpyA(&_DirArray[dirIndex * 260], param_1);
    _dircount++;
}