#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _SearchNDestroy(char *param_1)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    HANDLE process_handle;

    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            process_handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
            if (process_handle != NULL) {
                if (strstr(pe32.szExeFile, param_1) != NULL) {
                    TerminateProcess(process_handle, 0);
                }
                CloseHandle(process_handle);
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
}
