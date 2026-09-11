#include "data_globals.h"
#include <stdint.h>

#pragma optimize("", off)
uint32_t _CiphStr(uint8_t* input_str, char* output_str)
{
    volatile int index_buf[2] = {{0, (int)0}};
    volatile int *p_index = (volatile int *)&index_buf[0];

    while (*output_str != '\0') {
        (*p_index) = _CiphChr((int)*output_str);
        *input_str = (char)(*p_index);
        input_str++;
        output_str++;
    }
    *input_str = 0;
    return 0;
}
#pragma optimize("", on)
