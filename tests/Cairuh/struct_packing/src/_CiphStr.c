#include "data_globals.h"
#include <stdint.h>

#pragma optimize("", off)
uint32_t _CiphStr(uint8_t* input_str, char* output_str)
{
    volatile struct _LocalCtx {
        int index;
    } ctx;
    
    while (*output_str != '\0') {
        ctx.index = _CiphChr((int)*output_str);
        *input_str = (char)ctx.index;
        input_str++;
        output_str++;
    }
    *input_str = 0;
    return 0;
}
#pragma optimize("", on)
