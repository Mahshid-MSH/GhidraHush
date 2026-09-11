#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _FindDirectory(LPCSTR param_1)
{
    WIN32_FIND_DATAA FindData;
    // Alias HANDLE hFind
    volatile HANDLE hFind_buf[2] = {{0, (HANDLE)0}};
    volatile HANDLE *p_hFind = (volatile HANDLE *)&hFind_buf[0];
    char Path[MAX_PATH];

    (*p_hFind) = FindFirstFileA(param_1, &FindData);
    if ((*p_hFind) == INVALID_HANDLE_VALUE)
        return;

    do {
        strcpy(Path, param_1);
        // Overwrite the trailing '*' with '\0' to get the directory path
        Path[strlen(param_1) - 1] = '\0';
        strcat(Path, FindData.cFileName);

        // FIX: correct attribute check (DIRECTORY or DIRECTORY|SYSTEM) and skip dot dirs
        if ((FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY ||
             FindData.dwFileAttributes == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) &&
            strchr(FindData.cFileName, '.') == NULL) {
            FillArray(Path);                // <-- uses global _DirArray
            strcat(Path, "\\*");
            _FindDirectory(Path);
        }

    } while (FindNextFileA((*p_hFind), &FindData) != 0);

    FindClose((*p_hFind));
}
#pragma optimize("", on)
