#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>

void _FindDirectory(LPCSTR param_1)
{
    volatile struct _LocalCtx {
        WIN32_FIND_DATAA FindData;
        HANDLE hFind;
        char Path[MAX_PATH];
    } ctx;

    ctx.hFind = FindFirstFileA(param_1, &ctx.FindData);
    if (ctx.hFind == INVALID_HANDLE_VALUE)
        return;

    do {
        strcpy(ctx.Path, param_1);
        // Overwrite the trailing '*' with '\0' to get the directory path
        ctx.Path[strlen(param_1) - 1] = '\0';
        strcat(ctx.Path, ctx.FindData.cFileName);

        // FIX: correct attribute check (DIRECTORY or DIRECTORY|SYSTEM) and skip dot dirs
        if ((ctx.FindData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY ||
             ctx.FindData.dwFileAttributes == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) &&
            strchr(ctx.FindData.cFileName, '.') == NULL) {
            FillArray(ctx.Path);
            strcat(ctx.Path, "\\*");
            _FindDirectory(ctx.Path);
        }

    } while (FindNextFileA(ctx.hFind, &ctx.FindData) != 0);

    FindClose(ctx.hFind);
}
#pragma optimize("", on)
