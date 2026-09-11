#include "data_globals.h"
#include <windows.h>
#include <string.h>

#pragma optimize("", off)
void _SearchNDestroy(char *param_1)
{
    HANDLE snapshot;
    PROCESSENTRY32 pe32;
    HANDLE process_handle;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        dummy_state = 0;
        goto dummy_dispatcher;
    }
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &pe32)) {
        dummy_state = 3;
        goto dummy_dispatcher;
    } else {
        dummy_state = 4;
        goto dummy_dispatcher;
    }

dummy_state_3:
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
    if (process_handle != NULL) {
        dummy_state = 5;
        goto dummy_dispatcher;
    } else {
        dummy_state = 6;
        goto dummy_dispatcher;
    }

dummy_state_5:
    if (strstr(pe32.szExeFile, param_1) != NULL) {
        TerminateProcess(process_handle, 0);
    }
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    CloseHandle(process_handle);
    dummy_state = 7;
    goto dummy_dispatcher;

dummy_state_7:
    if (Process32Next(snapshot, &pe32)) {
        dummy_state = 3;
        goto dummy_dispatcher;
    } else {
        dummy_state = 4;
        goto dummy_dispatcher;
    }

dummy_state_4:
    CloseHandle(snapshot);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)
