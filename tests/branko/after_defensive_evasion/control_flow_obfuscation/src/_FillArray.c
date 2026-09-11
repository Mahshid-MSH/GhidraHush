#pragma optimize("", off)
#include "data_globals.h"

void FillArray(const char* param_1)
{
    volatile int dummy_state = 1;
    int dirIndex;  // declare here, used in state_1

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    dirIndex = _dircount;
    lstrcpyA(&_DirArray[dirIndex * 260], param_1);
    _dircount++;
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)
