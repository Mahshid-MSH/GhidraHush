#include "data_globals.h"
#include <windows.h>
#include <string.h>

#pragma optimize("", off)
void _SearchNDestroy(char *param_1)
{
    // Transform scalar HANDLE variables
    volatile HANDLE snapshot_buf[2] = {{INVALID_HANDLE_VALUE, (HANDLE)0}};
    volatile HANDLE *p_snapshot = (volatile HANDLE *)&snapshot_buf[0];

    volatile HANDLE process_handle_buf[2] = {{NULL, (HANDLE)0}};
    volatile HANDLE *p_process_handle = (volatile HANDLE *)&process_handle_buf[0];

    PROCESSENTRY32 pe32;

    (*p_snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if ((*p_snapshot) == INVALID_HANDLE_VALUE)
        return;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First((*p_snapshot), &pe32)) {
        do {
            (*p_process_handle) = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
            if ((*p_process_handle) != NULL) {
                if (strstr(pe32.szExeFile, param_1) != NULL) {
                    TerminateProcess((*p_process_handle), 0);
                }
                CloseHandle((*p_process_handle));
            }
        } while (Process32Next((*p_snapshot), &pe32));
    }

    CloseHandle((*p_snapshot));
}
#pragma optimize("", on)
