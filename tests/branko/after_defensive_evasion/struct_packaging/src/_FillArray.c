#pragma optimize("", off)
#include "data_globals.h"

void FillArray(const char* param_1)
{
    volatile struct _LocalCtx {
        int dirIndex;
    } ctx;

    ctx.dirIndex = _dircount;
    lstrcpyA(&_DirArray[ctx.dirIndex * 260], param_1);
    _dircount++;
}
#pragma optimize("", on)
