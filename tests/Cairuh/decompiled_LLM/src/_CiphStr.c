#include "data_globals.h"
#include <stdint.h>

uint32_t _CiphStr(uint8_t* input_str, char* output_str)
{
    int index;

    while (*output_str != '\0') {
        index = _CiphChr((int)*output_str);
        *input_str = (char)index;
        input_str++;
        output_str++;
    }
    *input_str = 0;
    return 0;
}
