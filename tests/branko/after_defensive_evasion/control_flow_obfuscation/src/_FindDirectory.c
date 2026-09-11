#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _FindDirectory(LPCSTR param_1)
{
    WIN32_FIND_DATAA FindData;
    HANDLE hFind;
    char Path[MAX_PATH];
    volatile int state = 1;

dispatcher:
    if (state == 1) goto state1;
    if (state == 2) goto state2;
    if (state == 3) goto state3;
    if (state == 4) goto state4;
    if (state == 0) goto end;

state1:
    hFind = FindFirstFileA(param_1, &FindData);
    if (hFind == INVALID_HANDLE_VALUE) {
        state = 0;
        goto dispatcher;
    }
    state = 2;
    goto dispatcher;

state2:
    strcpy(Path, param_1);
    Path[strlen(param_1) - 1] = '\0';
    strcat(Path, FindData.cFileName);

    if ((FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY ||
         FindData.dwFileAttributes == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) &&
        strchr(FindData.cFileName, '.') == NULL) {
        FillArray(Path);
        strcat(Path, "\\*");
        _FindDirectory(Path);
    }
    state = 3;
    goto dispatcher;

state3:
    if (FindNextFileA(hFind, &FindData) != 0) {
        state = 2;
    } else {
        state = 4;
    }
    goto dispatcher;

state4:
    FindClose(hFind);
    state = 0;
    goto dispatcher;

end:
    return;
}
#pragma optimize("", on)
