#include "data_globals.h"

char* Buffer = NULL;
char* VBuffer = NULL;
char* FBuffer = NULL;
char Virus[260] = {0};
char Drives[1024] = {0};
char buff[16] = {0};
char Status[32] = {0};
uint32_t _Status = 0;
uint8_t DAT_140008165 = 0;
uint8_t DAT_140008166 = 0;
char inf = 0;
uint32_t i = 0;
uint32_t j = 0;
int32_t maxSections = 0;
int32_t was_init = 0;
