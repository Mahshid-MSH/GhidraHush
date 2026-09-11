#include "data_globals.h"
#include <string.h>

#pragma optimize("", off)
uint32_t _CiphChr(uint32_t param_1)
{
    volatile struct _LocalCtx {
        char ListA[27];
        char ListB[27];
        char *Ptr;
    } ctx;
    
    strcpy(ctx.ListA, "abcdefghijklmnopqrstuvwxyz");
    strcpy(ctx.ListB, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    
    if ((ctx.Ptr = strchr(ctx.ListA, (int)param_1)) != NULL)
        return ctx.ListA[((ctx.Ptr - ctx.ListA) + 13) % 26];
    else if ((ctx.Ptr = strchr(ctx.ListB, (int)param_1)) != NULL)
        return ctx.ListB[((ctx.Ptr - ctx.ListB) + 13) % 26];
    else
        return param_1;
}
#pragma optimize("", on)
