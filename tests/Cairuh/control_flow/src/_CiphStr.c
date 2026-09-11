#include "data_globals.h"
#include <stdint.h>

#pragma optimize("", off)
uint32_t _CiphStr(uint8_t* input_str, char* output_str)
{
    volatile int opaque_cond = 0;
    __asm__ volatile ("movl $1, %0" : "=m"(opaque_cond));
    if (opaque_cond) {
        int index;

        while (*output_str != '\0') {
            index = _CiphChr((int)*output_str);
            *input_str = (char)index;
            input_str++;
            output_str++;
        }
        *input_str = 0;
        return 0;
    } else {
        return 0;
    }
}
#pragma optimize("", on)
