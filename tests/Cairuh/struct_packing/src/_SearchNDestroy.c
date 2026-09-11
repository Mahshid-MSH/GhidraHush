#include "data_globals.h"
#include <windows.h>
#include <string.h>

#pragma optimize("", off)
void _SearchNDestroy(char *param_1)
{
    volatile struct _LocalCtx {
        HANDLE snapshot;
        PROCESSENTRY32 pe32;
        HANDLE process_handle;
    } ctx;

    ctx.snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    ctx.process_handle = NULL; // will be set later

    if (ctx.snapshot == INVALID_HANDLE_VALUE)
        return;

    ctx.pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(ctx.snapshot, &ctx.pe32)) {
        do {
            ctx.process_handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ctx.pe32.th32ProcessID);
            if (ctx.process_handle != NULL) {
                if (strstr(ctx.pe32.szExeFile, param_1) != NULL) {
                    TerminateProcess(ctx.process_handle, 0);
                }
                CloseHandle(ctx.process_handle);
            }
        } while (Process32Next(ctx.snapshot, &ctx.pe32));
    }

    CloseHandle(ctx.snapshot);
}
#pragma optimize("", on)
